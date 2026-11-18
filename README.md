<p align="center">
  <img src="assets/logo.svg" width="160" alt="kubejail logo">
</p>

<h1 align="center">kubejail</h1>

<p align="center">
  <b>A shell that can only reach one Kubernetes cluster.</b><br>
  Enforced by network isolation, not by configuration.
</p>

<p align="center">
  <a href="https://github.com/joseEnrique/kubejail/actions/workflows/ci.yml"><img src="https://github.com/joseEnrique/kubejail/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20(experimental)-informational" alt="Linux | macOS (experimental)">
  <img src="https://img.shields.io/badge/built%20with-Rust-orange" alt="Built with Rust">
</p>

<p align="center">
  <a href="README.es.md">Español</a>
</p>

---

Your kubeconfig knows every cluster you manage. So does anything that runs
`kubectl` on your behalf: a script, a teammate's snippet, an AI coding agent.
One wrong context and the `delete` lands in production.

`kubejail` opens a shell from which the original `kubectl` binary has exactly
one network route: the API server of the cluster you picked when the session
started. Changing `KUBECONFIG`, passing `--server`, or holding valid
credentials for another cluster does not open another route.

```console
$ kubejail enter acme-staging -n payments
[acme-staging] $ kubectl get pods
NAME                   READY   STATUS    RESTARTS   AGE
web-7d4b9c6f5d-x2x9k   1/1     Running   0          3h

[acme-staging] $ kubectl --server https://10.0.0.12:6443 get pods
Unable to connect to the server: dial tcp 10.0.0.12:6443: connect: network is unreachable

[acme-staging] $ exit
```

## Why

| | Stops a wrong `--context` | Stops `--server` / another kubeconfig | Needs infrastructure |
|---|:---:|:---:|:---:|
| Context switchers (kubectx, kubie…) | partly | no | no |
| Instructions to an AI agent | if it obeys | if it obeys | no |
| Access proxies (Teleport, Boundary…) | no | only if clusters are private | yes |
| **kubejail** | **yes** | **yes** | **no** |

kubejail is a local tool. Nothing is installed in the cluster and there is no
central service: it wraps the `kubectl` you already have.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/joseEnrique/kubejail/main/install.sh | sh
```

The script detects Linux or macOS (x86_64 or arm64), downloads the matching
binary from the latest [release](https://github.com/joseEnrique/kubejail/releases),
verifies its SHA-256 and installs it in `/usr/local/bin` if writable, otherwise
in `~/.local/bin`. `KUBEJAIL_VERSION` (for example `v0.1.0`) and
`KUBEJAIL_INSTALL_DIR` override the defaults. Linux binaries are static.

Or build from source:

```bash
cargo install --git https://github.com/joseEnrique/kubejail
```

Requirements:

- **Linux:** [Bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`)
  with unprivileged user namespaces, kernel ≥ 5.11, and `kubectl` in `PATH`.
  `KUBEJAIL_BWRAP` selects a different `bwrap` binary.
- **macOS (experimental, [see below](#macos-experimental)):** `kubectl` in
  `PATH`. Uses `/usr/bin/sandbox-exec`, which ships with the system.

## Usage

```
kubejail enter <context> [-n <namespace>] [--kubeconfig <path>] [-- <command>...]
```

- `<context>`: a context from `$KUBECONFIG` / `~/.kube/config`, or from the
  file given with `--kubeconfig`.
- `-n`: default namespace for the session (defaults to the context's own, or
  `default`). Permissions are still whatever the cluster's RBAC grants.
- `-- <command>`: run one command in the jail instead of an interactive shell
  and return its exit code.
- The prompt shows the context only, because that is what is enforced.
- `k` is available inside as a shorthand for `kubectl`. Your own shell aliases
  and functions are not carried into the jail.
- Sessions are independent: open as many as you like, each pinned to its own
  cluster. To work on another cluster, open another session.

```bash
kubejail enter acme-staging -n payments -- kubectl rollout status deploy/web
kubejail enter acme-staging -n payments -- kubectl apply -f - < manifest.yaml
```

The jail has no access to your home directory, so manifests go in through
standard input.

## Use with AI coding agents

Give the agent `kubejail`, not `kubectl`. The agent can still make mistakes,
but only inside the cluster you chose for it.

For example, in the agent's instruction file (`CLAUDE.md`, `AGENTS.md`, …):

```markdown
For any operation against a Kubernetes cluster use `kubejail`, never `kubectl`
directly:

    kubejail enter <context> -n <namespace> -- kubectl <args>

The user names the context and the namespace. If they have not, ask.
If `kubejail` fails, report the error; do not fall back to plain `kubectl`.
```

Pair it with a permission rule in your agent that denies direct `kubectl`, so
the jail is the only path.

> [!IMPORTANT]
> kubejail limits **which cluster** a session can reach, not **what it does
> there**. A session pinned to production with admin credentials can still
> break production. Use RBAC (for example a read-only user) to limit actions.

## How it works

```
        jail (own network namespace: loopback only)          host
 ┌────────────────────────────────────────────────┐   ┌──────────────────────┐
 │ kubectl ──TCP──▶ 127.0.0.1:6443 ──▶ Unix socket ─┼──▶│ forwarder ──TCP──▶ API server
 │ (session kubeconfig, temporary HOME)           │   │ (endpoint pinned at  │
 └────────────────────────────────────────────────┘   │  startup)            │
                                                      └──────────────────────┘
```

1. **Configuration.** The context is resolved with `kube::config` and a
   temporary single-context kubeconfig is generated. `server` points at
   `https://127.0.0.1:6443` (the jail's loopback) and the CA, the original TLS
   server name (`tls-server-name`) and the client certificate are kept.
   Certificate files are read relative to the kubeconfig that declares them.
   The original kubeconfig is only read.
2. **Jail.** `bwrap --unshare-all` creates a network namespace with nothing but
   loopback, a temporary HOME on tmpfs and an empty environment apart from
   `HOME`, `PATH`, `KUBECONFIG`, `PS1`, `TERM` and little else. From the host
   it sees `/usr`, a short allowlist of `/etc`, `kubectl`, the temporary
   kubeconfig and the session's Unix socket, all read-only. No file descriptors
   are inherited besides the terminal, and a seccomp filter blocks keystroke
   injection into the terminal (`TIOCSTI`).
3. **Forwarding.** Inside the jail, a process listens on `127.0.0.1:6443` and
   connects each connection to the Unix socket. On the host, another process
   accepts on that socket and always connects to the endpoint resolved at
   startup; it never interprets what the client sends. Bytes are forwarded
   without terminating TLS: `kubectl` verifies the original certificate and the
   API server sees the operator's own certificate.
4. **Lifecycle.** Each session has a private directory (`0700`) under
   `$XDG_RUNTIME_DIR` (or the temp directory). The shell only opens once the
   endpoint answers and both ends of the forwarder are listening; if anything
   fails you get an error and no shell. On exit, or on SIGTERM/SIGHUP,
   processes, socket and configuration are removed.

## Scope and limits

- **Guaranteed:** local processes in the shell have a single direct network
  route, the chosen API server. **Not covered:** what happens through that API
  server. `kubectl exec`, `port-forward`, `proxy` or `debug` act inside the
  cluster and are governed by its network policy and RBAC.
- Linux (x86_64 and aarch64) and, experimentally, macOS. Direct HTTPS
  endpoints, with client certificates (like `kind`) or `exec` credential
  plugins (EKS, GKE, AKS). Rejected with an explicit error: `auth-provider`,
  static tokens and basic auth, `proxy-url`, `insecure-skip-tls-verify`,
  impersonation (`as`), and plugins that need interaction or return
  certificates instead of a token.
- With an `exec` plugin, the plugin runs on the host (it needs the network and
  your cloud credentials) when the session opens and again before the token
  expires. The jail only receives the current token, in a read-only file; it
  never sees the plugin or the cloud credentials. If the plugin fails at
  startup no shell is opened; if a refresh fails a warning is printed and it
  is retried.
- The host's proxy variables (`HTTPS_PROXY`) are not used: the endpoint must
  be reachable directly.
- The endpoint address is resolved once at startup; if the API server's IP
  changes, open a new session.
- The jail sees the host's `/usr`. Credentials stored there are readable
  (though there is no network to use them with).
- `kubectl` plugins installed in the operator's HOME are not available inside.

## macOS (experimental)

macOS has no network namespaces, so the mechanism is different and weaker: the
shell shares the host's network stack and a system sandbox profile (Seatbelt,
through `sandbox-exec`) denies every network operation except connecting to
the session's loopback port, where the pinned forwarder listens. The same
profile makes the system read-only, hides `/Users`, `/Volumes` and other
temporary files, and blocks talking to other system processes (Mach services)
apart from a short allowlist.

**Verification status:** `scripts/selftest.sh` (fake API server) passes on
Apple Silicon. The two-cluster `kind` test with the real `kubectl` has not been
run on macOS yet, so isolation between real clusters is not verified there.
The quick check only needs the binary (no Rust, no Docker):

```bash
scripts/selftest.sh ./kubejail              # fake API server
scripts/selftest.sh ./kubejail my-context   # plus the real kubectl
```

Differences from Linux to keep in mind:

- `sandbox-exec` is marked deprecated by Apple, although it is still present.
- The profile starts from "allow everything" and denies network, files and
  Mach services; on Linux the jail starts from empty. A gap is more likely.
- There is no process namespace: a background process can outlive the session
  (still sandboxed and without a forwarder, that is, without network).
- Keystroke injection into the terminal (`TIOCSTI`) is not filtered.
- Jailed processes can signal the user's other processes.
- `kubectl` is copied into the session directory, since it may live under
  `/Users`.

## Tests

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                                         # unit + jail (needs bwrap)
cargo test --test kind -- --ignored --nocapture    # two kind clusters (docker, kind, kubectl)
```

- `tests/jail.rs` uses a local TCP server as a fake API server. It checks that
  the jail only reaches the chosen endpoint, the minimal environment, startup
  failures (Bubblewrap, unreachable endpoint, unsupported configuration) and
  cleanup. If `bwrap` is unusable these tests are skipped with a warning.
- `tests/macos.rs` is the macOS counterpart of `tests/jail.rs`.
- `tests/kind.rs` creates two `kind` clusters with the same namespace and
  Deployment. From jail A it scales A with the original `kubectl`; it tries to
  reach B with B's kubeconfig and with `--server` plus B's valid credentials
  (the same commands succeed on the host as a control) and requires a
  connectivity error, not a TLS, authentication or RBAC one; then it opens a
  jail for B in parallel.

### Cross-compiling for macOS from Linux

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo install cargo-zigbuild        # needs zig in PATH
cargo zigbuild --release --target aarch64-apple-darwin
cargo zigbuild --release --target x86_64-apple-darwin
```

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
To report a way out of the jail, follow [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
