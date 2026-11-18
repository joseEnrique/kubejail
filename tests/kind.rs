//! Acceptance test with two disposable kind clusters and the real kubectl.
//!
//! Needs docker, kind and kubectl (plus bwrap on Linux), so it is ignored by
//! default:
//!
//!     cargo test --test kind -- --ignored --nocapture
//!
//! Set KUBEJAIL_KEEP_CLUSTERS=1 to keep the clusters for debugging.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const NAMESPACE: &str = "demo";

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn run(cmd: &mut Command) -> Output {
    cmd.output()
        .unwrap_or_else(|e| panic!("cannot run {cmd:?}: {e}"))
}

fn run_ok(cmd: &mut Command) -> String {
    let out = run(cmd);
    assert!(
        out.status.success(),
        "{cmd:?} failed\nstdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    text(&out.stdout)
}

fn with_stdin(cmd: &mut Command, input: &[u8]) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

struct Cluster {
    name: String,
    kubeconfig: PathBuf,
}

impl Cluster {
    fn create(name: &str, dir: &Path) -> Cluster {
        let cluster = Cluster {
            name: name.to_string(),
            kubeconfig: dir.join(format!("{name}.yaml")),
        };
        let _ = run(Command::new("kind").args(["delete", "cluster", "--name", name]));
        run_ok(
            Command::new("kind")
                .args([
                    "create",
                    "cluster",
                    "--wait",
                    "180s",
                    "--name",
                    name,
                    "--kubeconfig",
                ])
                .arg(&cluster.kubeconfig),
        );
        cluster
    }

    fn context(&self) -> String {
        format!("kind-{}", self.name)
    }

    /// kubectl on the host, with this cluster's kubeconfig.
    fn kubectl(&self, args: &[&str]) -> String {
        run_ok(
            Command::new("kubectl")
                .arg("--kubeconfig")
                .arg(&self.kubeconfig)
                .args(["-n", NAMESPACE])
                .args(args),
        )
    }

    fn replicas(&self) -> String {
        self.kubectl(&[
            "get",
            "deployment",
            "web",
            "-o",
            "jsonpath={.spec.replicas}",
        ])
    }

    fn server(&self) -> String {
        self.kubectl(&[
            "config",
            "view",
            "--raw",
            "-o",
            "jsonpath={.clusters[0].cluster.server}",
        ])
    }

    #[cfg(target_os = "linux")]
    fn node_ip(&self) -> String {
        run_ok(Command::new("docker").args([
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            &format!("{}-control-plane", self.name),
        ]))
        .trim()
        .to_string()
    }

    /// A jailed `bash -c script` for this cluster.
    fn jail(&self, runtime_dir: &Path, script: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kubejail"));
        cmd.args(["enter", &self.context(), "-n", NAMESPACE, "--kubeconfig"])
            .arg(&self.kubeconfig)
            .args(["--", "bash", "-c", script])
            .env("XDG_RUNTIME_DIR", runtime_dir)
            .stdin(Stdio::null());
        cmd
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        if std::env::var_os("KUBEJAIL_KEEP_CLUSTERS").is_none() {
            let _ = run(Command::new("kind").args(["delete", "cluster", "--name", &self.name]));
        }
    }
}

/// Reads cluster B's kubeconfig from stdin into the current directory and
/// splits out its credentials, using only local kubectl operations.
const UNPACK_B: &str = r#"
set -e
cat > b.yaml
field() { kubectl --kubeconfig b.yaml config view --raw -o "jsonpath={$1}" | base64 -d; }
field '.clusters[0].cluster.certificate-authority-data' > ca.crt
field '.users[0].user.client-certificate-data' > client.crt
field '.users[0].user.client-key-data' > client.key
"#;

#[test]
#[ignore = "needs docker, kind, kubectl and bwrap; run with --ignored"]
fn jail_is_confined_to_its_cluster() {
    for (tool, args) in [
        ("docker", &["ps"][..]),
        ("kind", &["version"]),
        ("kubectl", &["version", "--client"]),
        #[cfg(target_os = "linux")]
        ("bwrap", &["--unshare-all", "--ro-bind", "/", "/", "true"]),
    ] {
        let ok = Command::new(tool)
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success());
        assert!(ok, "prerequisite failed: `{tool} {}`", args.join(" "));
    }

    let dir = tempfile::Builder::new()
        .prefix("kj")
        .tempdir_in("/tmp")
        .unwrap();
    let runtime_dir = dir.path().join("run");
    std::fs::create_dir(&runtime_dir).unwrap();
    let rt = runtime_dir.as_path();

    let (a, b) = std::thread::scope(|s| {
        let a = s.spawn(|| Cluster::create("kubejail-it-a", dir.path()));
        let b = s.spawn(|| Cluster::create("kubejail-it-b", dir.path()));
        (a.join().unwrap(), b.join().unwrap())
    });

    // Same namespace and Deployment in both; the host credentials work.
    for cluster in [&a, &b] {
        cluster.kubectl(&["create", "namespace", NAMESPACE]);
        cluster.kubectl(&[
            "create",
            "deployment",
            "web",
            "--image=registry.k8s.io/pause:3.10",
            "--replicas=1",
        ]);
        assert_eq!(cluster.replicas(), "1");
    }
    let original_a = std::fs::read(&a.kubeconfig).unwrap();

    // --- Jail A: the original kubectl reads and scales A, and only A. ---
    let out = run_ok(&mut a.jail(
        rt,
        r#"set -e
kubectl get deployment web -o 'jsonpath={.spec.replicas}'; echo
"$(command -v kubectl)" scale deployment web --replicas=3
kubectl get deployment web -o 'jsonpath={.spec.replicas}'; echo"#,
    ));
    assert!(out.starts_with("1\n") && out.ends_with("3\n"), "{out}");
    assert_eq!((a.replicas().as_str(), b.replicas().as_str()), ("3", "1"));

    // --- Jail A cannot reach B, even with B's valid credentials. ---
    let b_kubeconfig = std::fs::read(&b.kubeconfig).unwrap();
    let get = "-n demo get deployment web -o 'jsonpath={.spec.replicas}'";
    let creds = "--kubeconfig /dev/null --certificate-authority ca.crt \
                 --client-certificate client.crt --client-key client.key";
    let attempts = [
        (
            "B's own kubeconfig".to_string(),
            format!("kubectl --kubeconfig b.yaml {get}"),
        ),
        (
            "--server with B's published endpoint".to_string(),
            format!("kubectl --server {} {creds} {get}", b.server()),
        ),
        // The node's own address is only routable from a Linux host.
        #[cfg(target_os = "linux")]
        (
            "--server with B's node address".to_string(),
            format!(
                "kubectl --server https://{}:6443 {creds} {get}",
                b.node_ip()
            ),
        ),
    ];
    for (what, kubectl) in &attempts {
        let script = format!("{UNPACK_B}\n{kubectl} --request-timeout=10s");

        // Control: the very same script works on the host, so the
        // credentials, CA and endpoint are all valid.
        let host_dir = tempfile::tempdir_in(dir.path()).unwrap();
        let host = with_stdin(
            Command::new("bash")
                .args(["-c", &script])
                .current_dir(&host_dir),
            &b_kubeconfig,
        );
        assert!(
            host.status.success(),
            "host control for {what}: {}",
            text(&host.stderr)
        );
        assert_eq!(text(&host.stdout), "1", "host control for {what}");

        let jailed = with_stdin(&mut a.jail(rt, &script), &b_kubeconfig);
        let stderr = text(&jailed.stderr).to_lowercase();
        println!("jail A -> B via {what}: {}", stderr.trim());
        assert!(!jailed.status.success(), "{what}: jail A reached cluster B");
        assert_eq!(text(&jailed.stdout), "", "{what}");
        let connectivity = [
            "connection refused",
            "network is unreachable",
            "no route to host",
        ];
        assert!(
            connectivity.iter().any(|m| stderr.contains(m)),
            "{what}: expected a connectivity error, got: {stderr}"
        );
        for other in [
            "x509",
            "certificate",
            "tls",
            "unauthorized",
            "forbidden",
            "credentials",
        ] {
            assert!(
                !stderr.contains(other),
                "{what}: unexpected {other:?} error: {stderr}"
            );
        }
    }
    assert_eq!((a.replicas().as_str(), b.replicas().as_str()), ("3", "1"));

    // --- A second jail, for B, works while A's session is still open. ---
    let (a_out, a_end, b_end) = std::thread::scope(|s| {
        let a_session = s.spawn(|| {
            let out = run_ok(&mut a.jail(
                rt,
                r#"set -e
kubectl get deployment web -o 'jsonpath={.spec.replicas}'; echo
sleep 15
kubectl get deployment web -o 'jsonpath={.spec.replicas}'; echo"#,
            ));
            (out, Instant::now())
        });
        std::thread::sleep(Duration::from_secs(2));
        let out = run_ok(&mut b.jail(
            rt,
            r#"set -e
kubectl get deployment web -o 'jsonpath={.spec.replicas}'; echo
kubectl scale deployment web --replicas=2 >/dev/null
kubectl get deployment web -o 'jsonpath={.spec.replicas}'; echo"#,
        ));
        let b_end = Instant::now();
        assert_eq!(out, "1\n2\n");
        let (a_out, a_end) = a_session.join().unwrap();
        (a_out, a_end, b_end)
    });
    assert!(
        b_end < a_end,
        "jail B was meant to run while jail A was open"
    );
    assert_eq!(a_out, "3\n3\n");
    assert_eq!((a.replicas().as_str(), b.replicas().as_str()), ("3", "2"));

    // The operator's kubeconfig is untouched and no session files remain.
    assert_eq!(std::fs::read(&a.kubeconfig).unwrap(), original_a);
    assert_eq!(std::fs::read_dir(rt).unwrap().count(), 0);
}
