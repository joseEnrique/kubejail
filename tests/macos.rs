//! macOS sandbox behaviour against a fake "API server" (a plain TCP
//! responder). Linux counterpart: `tests/jail.rs`. The two-cluster proof
//! with the real kubectl is `tests/kind.rs` on both platforms.
#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const CERT: &str = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg=="; // "-----BEGIN CERTIFICATE-----\n"

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
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("run")).unwrap();
        let kubeconfig = format!(
            r#"apiVersion: v1
kind: Config
clusters:
- name: fake
  cluster: {{server: "https://127.0.0.1:{server_port}", certificate-authority-data: {CERT}}}
users:
- name: op
  user: {{client-certificate-data: {CERT}, client-key-data: {CERT}}}
contexts:
- name: test
  context: {{cluster: fake, user: op}}
"#
        );
        std::fs::write(dir.path().join("config.yaml"), kubeconfig).unwrap();
        Fixture { dir }
    }

    fn kubeconfig(&self) -> PathBuf {
        self.dir.path().join("config.yaml")
    }

    fn command(&self, script: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kubejail"));
        cmd.args(["enter", "test", "-n", "payments", "--kubeconfig"])
            .arg(self.kubeconfig())
            .args(["--", "/bin/bash", "-c", script])
            // Session directories go under $TMPDIR on macOS.
            .env("TMPDIR", self.dir.path().join("run"))
            .env("HOST_SECRET", "leak-me")
            .stdin(Stdio::null());
        cmd
    }

    fn run(&self, script: &str) -> Output {
        self.command(script).output().unwrap()
    }

    fn session_dirs(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.dir.path().join("run"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn sandbox_reaches_only_the_selected_endpoint() {
    let api = responder("api");
    let other = responder("other");
    // Positive control: the other service is reachable from the host.
    std::net::TcpStream::connect(("127.0.0.1", other)).unwrap();

    let fx = Fixture::new(api);
    let original = std::fs::read(fx.kubeconfig()).unwrap();
    let operator_home = std::env::var("HOME").unwrap();
    let script = format!(
        r#"
port=$(sed -n 's/.*127\.0\.0\.1:\([0-9]*\).*/\1/p' "$KUBECONFIG")
exec 3<>/dev/tcp/127.0.0.1/$port && echo ping >&3 && read -r reply <&3 && echo "api=$reply"
exec 3>&-
if (exec 4<>/dev/tcp/127.0.0.1/{other}) 2>/dev/null; then echo other=open; else echo other=closed; fi
if (exec 4<>/dev/tcp/127.0.0.1/{api}) 2>/dev/null; then echo direct=open; else echo direct=closed; fi
if (exec 4<>/dev/tcp/1.1.1.1/443) 2>/dev/null; then echo internet=open; else echo internet=closed; fi
echo "secret=${{HOST_SECRET:-unset}} ctx=$KUBEJAIL_CONTEXT ns=$KUBEJAIL_NAMESPACE"
case "$HOME" in */kubejail-*/home) echo home=session;; *) echo "home=$HOME";; esac
if ls '{operator_home}' >/dev/null 2>&1; then echo operator_home=readable; else echo operator_home=hidden; fi
if cat '{host_cfg}' >/dev/null 2>&1; then echo original=readable; else echo original=hidden; fi
if touch /tmp/kubejail-escape 2>/dev/null; then echo tmp=writable; else echo tmp=readonly; fi
touch "$HOME/scratch" && echo home_write=ok
"#,
        host_cfg = fx.kubeconfig().display()
    );
    let out = fx.run(&script);
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "{stdout}\n{}", text(&out.stderr));
    for expected in [
        "api=api:ping",
        "other=closed",
        "direct=closed",
        "internet=closed",
        "secret=unset ctx=test ns=payments",
        "home=session",
        "operator_home=hidden",
        "original=hidden",
        "tmp=readonly",
        "home_write=ok",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in:\n{stdout}"
        );
    }
    assert_eq!(std::fs::read(fx.kubeconfig()).unwrap(), original);
    assert_eq!(fx.session_dirs(), Vec::<PathBuf>::new());
}

#[test]
fn exit_code_is_propagated() {
    let fx = Fixture::new(responder("api"));
    assert_eq!(fx.run("exit 7").status.code(), Some(7));
}

#[test]
fn sandbox_failure_opens_no_shell_and_cleans_up() {
    let fx = Fixture::new(responder("api"));
    for sandbox_exec in ["/usr/bin/false", "/nonexistent/sandbox-exec"] {
        let out = fx
            .command("echo SHELL_RAN")
            .env("KUBEJAIL_SANDBOX_EXEC", sandbox_exec)
            .output()
            .unwrap();
        let stderr = text(&out.stderr);
        assert!(!out.status.success());
        assert!(stderr.contains("no shell was opened"), "{stderr}");
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
    let out = fx.run("echo SHELL_RAN");
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("cannot reach API server"));
    assert!(!text(&out.stdout).contains("SHELL_RAN"));
    assert_eq!(fx.session_dirs(), Vec::<PathBuf>::new());
}
