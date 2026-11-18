//! Jail behaviour against a fake "API server" (a plain TCP responder). The
//! forwarder never looks at the bytes, so no cluster is needed here; the
//! real-kubectl, two-cluster proof lives in `tests/kind.rs`.
//!
//! Needs a working Bubblewrap; tests are skipped (loudly) without it.
//! The macOS counterpart is `tests/macos.rs`.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const CERT: &str = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg=="; // "-----BEGIN CERTIFICATE-----\n"

fn bwrap_available() -> bool {
    let ok = Command::new("bwrap")
        .args(["--unshare-all", "--ro-bind", "/", "/", "true"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("SKIPPED: Bubblewrap (bwrap) cannot create namespaces here");
    }
    ok
}

/// Answers each connection with "<tag>:<first line>".
fn responder(tag: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).is_ok() {
                let _ = (&stream).write_all(format!("{tag}:{line}").as_bytes());
            }
        }
    });
    port
}

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new(server_port: u16) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("kj")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::create_dir(dir.path().join("run")).unwrap();
        let kubeconfig = format!(
            r#"apiVersion: v1
kind: Config
clusters:
- name: fake
  cluster: {{server: "https://127.0.0.1:{server_port}", certificate-authority-data: {CERT}}}
- name: elsewhere
  cluster: {{server: "https://elsewhere.invalid"}}
users:
- name: op
  user: {{client-certificate-data: {CERT}, client-key-data: {CERT}}}
- name: other-op
  user: {{token: other-cluster-token}}
contexts:
- name: test
  context: {{cluster: fake, user: op, namespace: from-context}}
- name: elsewhere
  context: {{cluster: elsewhere, user: other-op}}
"#
        );
        std::fs::write(dir.path().join("config.yaml"), kubeconfig).unwrap();
        Fixture { dir }
    }

    fn kubeconfig(&self) -> PathBuf {
        self.dir.path().join("config.yaml")
    }

    fn runtime_dir(&self) -> PathBuf {
        self.dir.path().join("run")
    }

    fn command(&self, extra: &[&str], script: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kubejail"));
        cmd.args(["enter", "test", "--kubeconfig"])
            .arg(self.kubeconfig())
            .args(extra)
            .args(["--", "bash", "-c", script])
            .env("XDG_RUNTIME_DIR", self.runtime_dir())
            .env("HOST_SECRET", "leak-me")
            .stdin(Stdio::null());
        cmd
    }

    fn run(&self, extra: &[&str], script: &str) -> Output {
        self.command(extra, script).output().unwrap()
    }

    fn session_dirs(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.runtime_dir())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn mode(path: &Path) -> u32 {
    path.metadata().unwrap().permissions().mode() & 0o777
}

#[test]
fn jail_reaches_only_the_selected_endpoint() {
    if !bwrap_available() {
        return;
    }
    let api = responder("api");
    let other = responder("other");
    // Positive control: the other service is reachable from the host.
    std::net::TcpStream::connect(("127.0.0.1", other)).unwrap();

    let fx = Fixture::new(api);
    let original = std::fs::read(fx.kubeconfig()).unwrap();
    let script = format!(
        r#"
exec 3<>/dev/tcp/127.0.0.1/6443 && echo ping >&3 && read -r reply <&3 && echo "api=$reply"
if (exec 4<>/dev/tcp/127.0.0.1/{other}) 2>/dev/null; then echo other=open; else echo other=closed; fi
if (exec 4<>/dev/tcp/127.0.0.1/{api}) 2>/dev/null; then echo direct=open; else echo direct=closed; fi
echo "ifaces=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\n' ',')"
echo "home=$HOME secret=${{HOST_SECRET:-unset}} ctx=$KUBEJAIL_CONTEXT ns=$KUBEJAIL_NAMESPACE"
echo "homes=$(ls /home | tr '\n' ',')"
[ -e '{host_cfg}' ] && echo original=visible || echo original=hidden
exec 3>&-
echo "fds=$(ls /proc/self/fd | tr '\n' ',')"
echo "--- kubeconfig"
cat "$KUBECONFIG"
"#,
        host_cfg = fx.kubeconfig().display()
    );
    let out = fx.run(&["-n", "payments"], &script);
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "{stdout}\n{}", text(&out.stderr));

    // Forwarding works, and only towards the selected endpoint.
    assert!(stdout.contains("api=api:ping"), "{stdout}");
    assert!(stdout.contains("other=closed"), "{stdout}");
    assert!(stdout.contains("direct=closed"), "{stdout}");
    assert!(stdout.contains("ifaces=lo,\n"), "{stdout}");
    // Minimal environment, throwaway HOME, nothing of the host's.
    assert!(
        stdout.contains("home=/home/kubejail secret=unset ctx=test ns=payments"),
        "{stdout}"
    );
    assert!(stdout.contains("homes=kubejail,\n"), "{stdout}");
    assert!(stdout.contains("original=hidden"), "{stdout}");
    // Only stdio plus the descriptor `ls` itself opens on /proc/self/fd.
    assert!(stdout.contains("fds=0,1,2,3,\n"), "{stdout}");
    // The jailed kubeconfig has just the selected context, on loopback.
    let (_, jailed) = stdout.split_once("--- kubeconfig\n").unwrap();
    let jailed: serde_json::Value = serde_json::from_str(jailed).unwrap();
    assert_eq!(
        jailed["clusters"][0]["cluster"]["server"],
        "https://127.0.0.1:6443"
    );
    assert_eq!(jailed["contexts"][0]["context"]["namespace"], "payments");
    assert!(!stdout.contains("other-cluster-token") && !stdout.contains("elsewhere"));

    // The operator's kubeconfig is untouched and nothing is left behind.
    assert_eq!(std::fs::read(fx.kubeconfig()).unwrap(), original);
    assert_eq!(fx.session_dirs(), Vec::<PathBuf>::new());
}

#[test]
fn exit_code_is_propagated_and_two_sessions_coexist() {
    if !bwrap_available() {
        return;
    }
    let (fx_a, fx_b) = (Fixture::new(responder("A")), Fixture::new(responder("B")));
    let script = r#"exec 3<>/dev/tcp/127.0.0.1/6443; echo hi >&3; sleep 1; read -r r <&3; echo "$r"; exit 7"#;
    let a = std::thread::spawn(move || fx_a.run(&[], script));
    let b = fx_b.run(&[], script);
    let a = a.join().unwrap();
    assert_eq!(text(&a.stdout), "A:hi\n");
    assert_eq!(text(&b.stdout), "B:hi\n");
    assert_eq!((a.status.code(), b.status.code()), (Some(7), Some(7)));
}

#[test]
fn terminal_injection_ioctl_is_blocked() {
    if !bwrap_available() || !Path::new("/usr/bin/perl").exists() {
        eprintln!("SKIPPED: needs bwrap and perl");
        return;
    }
    let fx = Fixture::new(responder("api"));
    // TIOCSTI on a non-terminal is ENOTTY (25) unless the filter answers
    // first with EPERM (1).
    let out = fx.run(
        &[],
        r#"perl -e '$x = "x"; ioctl(STDIN, 0x5412, $x); print $! + 0'"#,
    );
    assert_eq!(text(&out.stdout), "1", "{}", text(&out.stderr));
}

#[test]
fn bubblewrap_failure_opens_no_shell_and_cleans_up() {
    let fx = Fixture::new(responder("api"));
    for (bwrap, expected) in [
        ("/bin/false", "no shell was opened"),
        ("/nonexistent/bwrap", "cannot start Bubblewrap"),
    ] {
        let out = fx
            .command(&[], "echo SHELL_RAN")
            .env("KUBEJAIL_BWRAP", bwrap)
            .output()
            .unwrap();
        let stderr = text(&out.stderr);
        assert!(!out.status.success());
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!text(&out.stdout).contains("SHELL_RAN"));
        assert_eq!(fx.session_dirs(), Vec::<PathBuf>::new());
    }
}

#[test]
fn unreachable_endpoint_opens_no_shell_and_cleans_up() {
    // A port that was just closed: nothing listens there.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let fx = Fixture::new(port);
    let out = fx.run(&[], "echo SHELL_RAN");
    let stderr = text(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("cannot reach API server"), "{stderr}");
    assert!(!text(&out.stdout).contains("SHELL_RAN"));
    assert_eq!(fx.session_dirs(), Vec::<PathBuf>::new());
}

#[test]
fn unsupported_context_fails_before_anything_is_created() {
    let fx = Fixture::new(responder("api"));
    let out = Command::new(env!("CARGO_BIN_EXE_kubejail"))
        .args(["enter", "elsewhere", "--kubeconfig"])
        .arg(fx.kubeconfig())
        .args(["--", "echo", "SHELL_RAN"])
        .env("XDG_RUNTIME_DIR", fx.runtime_dir())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("only client certificates"));
    assert!(!text(&out.stdout).contains("SHELL_RAN"));
    assert_eq!(fx.session_dirs(), Vec::<PathBuf>::new());
}

#[test]
fn session_directory_is_private_and_removed_on_sigterm() {
    if !bwrap_available() {
        return;
    }
    let fx = Fixture::new(responder("api"));
    let mut child = fx
        .command(&[], "echo started; sleep 61.7")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // The shell only runs once the session is fully set up.
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "started\n");

    let dirs = fx.session_dirs();
    assert_eq!(dirs.len(), 1);
    assert_eq!(mode(&dirs[0]), 0o700);
    assert_eq!(mode(&dirs[0].join("kubeconfig")), 0o600);
    assert!(dirs[0].join("api.sock").exists());

    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let started = Instant::now();
    let status = child.wait().unwrap();
    assert!(!status.success());
    assert!(started.elapsed() < Duration::from_secs(10));
    // The jailed process is gone too, not just the session files.
    std::thread::sleep(Duration::from_millis(300));
    let survivors: Vec<_> = std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| std::fs::read(e.unwrap().path().join("cmdline")).ok())
        .filter(|cmdline| cmdline == b"sleep\x0061.7\x00")
        .collect();
    assert!(survivors.is_empty());
    assert_eq!(fx.session_dirs(), Vec::<PathBuf>::new());
}

/// A kubeconfig whose user authenticates through a credential plugin.
fn exec_fixture(plugin: &str) -> (Fixture, Command) {
    let fx = Fixture::new(responder("api"));
    let script = fx.dir.path().join("plugin.sh");
    std::fs::write(&script, plugin).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let kubeconfig = std::fs::read_to_string(fx.kubeconfig()).unwrap()
        + &format!(
            r#"- name: cloud
  context: {{cluster: fake, user: cloud-op}}
users:
- name: cloud-op
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: {}
      env: [{{name: COUNT_FILE, value: {}}}]
"#,
            script.display(),
            fx.dir.path().join("count").display()
        );
    // `users` appears twice in the YAML above; keep a single list.
    let kubeconfig = kubeconfig.replacen("users:\n- name: cloud-op", "- name: cloud-op", 1);
    let (head, contexts) = kubeconfig.split_once("contexts:\n").unwrap();
    let (contexts, cloud_user) = contexts.split_once("- name: cloud-op").unwrap();
    let kubeconfig = format!("{head}- name: cloud-op{cloud_user}contexts:\n{contexts}");
    std::fs::write(fx.kubeconfig(), kubeconfig).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kubejail"));
    cmd.args(["enter", "cloud", "--kubeconfig"])
        .arg(fx.kubeconfig())
        .env("XDG_RUNTIME_DIR", fx.runtime_dir())
        .stdin(Stdio::null());
    (fx, cmd)
}

#[test]
fn credential_plugin_runs_on_the_host_and_its_token_is_refreshed() {
    if !bwrap_available() {
        return;
    }
    // Each run issues a new token that expires four seconds later.
    let (fx, mut cmd) = exec_fixture(
        r#"#!/bin/sh
n=$(( $(cat "$COUNT_FILE" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$COUNT_FILE"
exp=$(date -u -d '+4 seconds' +%Y-%m-%dT%H:%M:%SZ)
echo "{\"kind\":\"ExecCredential\",\"status\":{\"token\":\"tok-$n\",\"expirationTimestamp\":\"$exp\"}}"
"#,
    );
    let out = cmd
        .args([
            "--",
            "bash",
            "-c",
            r#"echo "first=$(cat /run/kubejail/auth/token)"
grep -o '"tokenFile": "[^"]*"' "$KUBECONFIG"
grep -c 'plugin.sh\|exec' "$KUBECONFIG"
touch /run/kubejail/auth/x 2>/dev/null && echo auth=writable || echo auth=readonly
sleep 5
echo "later=$(cat /run/kubejail/auth/token)""#,
        ])
        .output()
        .unwrap();
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "{stdout}\n{}", text(&out.stderr));
    assert!(stdout.contains("first=tok-1\n"), "{stdout}");
    assert!(
        stdout.contains(r#""tokenFile": "/run/kubejail/auth/token""#),
        "{stdout}"
    );
    // The plugin itself is not part of the jailed kubeconfig.
    assert!(stdout.contains("\n0\n"), "{stdout}");
    assert!(stdout.contains("auth=readonly"), "{stdout}");
    let later = stdout.split("later=tok-").nth(1).unwrap().trim();
    assert!(later.parse::<u32>().unwrap() >= 2, "{stdout}");
    assert_eq!(fx.session_dirs(), Vec::<PathBuf>::new());
}

#[test]
fn failing_credential_plugin_opens_no_shell() {
    let (fx, mut cmd) = exec_fixture("#!/bin/sh\necho 'no cloud session' >&2\nexit 1\n");
    let out = cmd.args(["--", "echo", "SHELL_RAN"]).output().unwrap();
    let stderr = text(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("no cloud session"), "{stderr}");
    assert!(stderr.contains("cannot obtain credentials"), "{stderr}");
    assert!(!text(&out.stdout).contains("SHELL_RAN"));
    assert_eq!(fx.session_dirs(), Vec::<PathBuf>::new());
}
