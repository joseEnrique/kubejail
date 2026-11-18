# Contributing

Thanks for your interest in kubejail.

## Before you open a pull request

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

If your change touches the jail, the forwarder or the generated kubeconfig,
also run the two-cluster test (needs Docker, `kind` and `kubectl`):

```bash
cargo test --test kind -- --ignored --nocapture
```

## Guidelines

- Isolation claims need a test. A change that widens what the jail can see or
  reach must explain why and come with a test showing what is still blocked.
- Unsupported kubeconfig features should fail with a clear error before any
  shell is opened, rather than degrade silently.
- Keep the host forwarder dumb: it connects to the endpoint pinned at startup
  and never reads a destination from the client.
- Keep dependencies few; every crate is part of the trusted base.

## Reporting bugs

Open an issue with your OS, kernel (`uname -r`), `bwrap --version` or macOS
version, the command you ran and the full error. Remove cluster names,
endpoints and account IDs you do not want to be public.

Security problems (a way to reach something other than the chosen API server,
or to read host files) should follow [SECURITY.md](SECURITY.md) instead.
