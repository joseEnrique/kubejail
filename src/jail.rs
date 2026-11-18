//! Bubblewrap command line and the seccomp filter for the jail.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Loopback port the jailed kubeconfig points at. Every jail has its own
/// network namespace, so the port can be the same in all of them.
pub const JAIL_PORT: u16 = 6443;

pub const JAIL_HOME: &str = "/home/kubejail";
pub const JAIL_SOCKET: &str = "/run/kubejail/api.sock";
/// Where the session's token (credential plugins) appears. The whole
/// directory is bound so the host can replace the token atomically.
pub const JAIL_AUTH_DIR: &str = "/run/kubejail/auth";
const JAIL_SELF: &str = "/opt/kubejail/libexec/kubejail";
const JAIL_BIN: &str = "/opt/kubejail/bin";

/// The only parts of /etc the jail gets: dynamic loader, CA bundle, terminal
/// and user-name lookups. No resolver config, no host credentials.
const ETC_ALLOWLIST: &[&str] = &[
    "ld.so.cache",
    "ld.so.conf",
    "ld.so.conf.d",
    "alternatives",
    "ssl/certs",
    "ca-certificates",
    "terminfo",
    "localtime",
    "nsswitch.conf",
    "passwd",
    "group",
    "inputrc",
];

pub struct JailSpec<'a> {
    pub kubeconfig: &'a Path,
    pub auth_dir: &'a Path,
    pub socket: &'a Path,
    pub self_exe: &'a Path,
    pub kubectl: Option<&'a Path>,
    pub context: &'a str,
    pub namespace: &'a str,
    pub term: Option<OsString>,
    /// Descriptors bwrap inherits: the seccomp program and the readiness pipe.
    pub seccomp_fd: i32,
    pub ready_fd: i32,
    /// Empty means "interactive shell".
    pub command: &'a [OsString],
}

pub fn bwrap_args(spec: &JailSpec) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    let mut add = |items: &[&dyn AsRef<std::ffi::OsStr>]| {
        args.extend(items.iter().map(|i| i.as_ref().to_os_string()));
    };

    // New user, pid, ipc, uts, cgroup and *network* namespaces. bwrap brings
    // up loopback in the new network namespace and nothing else.
    add(&[&"--unshare-all", &"--die-with-parent", &"--clearenv"]);
    add(&[&"--hostname", &"kubejail"]);
    add(&[&"--seccomp", &spec.seccomp_fd.to_string()]);

    // System binaries and libraries, read-only.
    add(&[&"--ro-bind", &"/usr", &"/usr"]);
    for dir in ["/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"] {
        let path = Path::new(dir);
        if let Ok(target) = std::fs::read_link(path) {
            add(&[&"--symlink", &target, &dir]);
        } else if path.is_dir() {
            add(&[&"--ro-bind", &dir, &dir]);
        }
    }
    for entry in ETC_ALLOWLIST {
        let path = format!("/etc/{entry}");
        add(&[&"--ro-bind-try", &path, &path]);
    }
    add(&[&"--proc", &"/proc", &"--dev", &"/dev", &"--tmpfs", &"/tmp"]);

    // Throwaway HOME on the jail's tmpfs root; only the session's kubeconfig,
    // its socket, this binary and kubectl come from the host.
    let kube_dir = format!("{JAIL_HOME}/.kube");
    let jail_kubeconfig = format!("{kube_dir}/config");
    add(&[&"--dir", &JAIL_HOME, &"--dir", &kube_dir]);
    add(&[&"--ro-bind", &spec.kubeconfig, &jail_kubeconfig]);
    add(&[&"--ro-bind", &spec.auth_dir, &JAIL_AUTH_DIR]);
    add(&[&"--ro-bind", &spec.socket, &JAIL_SOCKET]);
    add(&[&"--ro-bind", &spec.self_exe, &JAIL_SELF]);
    if let Some(kubectl) = spec.kubectl {
        add(&[&"--ro-bind", &kubectl, &format!("{JAIL_BIN}/kubectl")]);
    }

    let path = format!("{JAIL_BIN}:/usr/local/bin:/usr/bin:/bin");
    let prompt = crate::session::prompt(spec.context, spec.namespace);
    add(&[&"--setenv", &"HOME", &JAIL_HOME]);
    add(&[&"--setenv", &"PATH", &path]);
    add(&[&"--setenv", &"KUBECONFIG", &jail_kubeconfig]);
    add(&[&"--setenv", &"PS1", &prompt]);
    add(&[&"--setenv", &"KUBEJAIL_CONTEXT", &spec.context]);
    add(&[&"--setenv", &"KUBEJAIL_NAMESPACE", &spec.namespace]);
    add(&[&"--setenv", &"LANG", &"C.UTF-8"]);
    if let Some(term) = &spec.term {
        add(&[&"--setenv", &"TERM", term]);
    }
    add(&[&"--chdir", &JAIL_HOME]);

    add(&[&"--", &JAIL_SELF, &"jail-init"]);
    add(&[&"--ready-fd", &spec.ready_fd.to_string(), &"--"]);
    if spec.command.is_empty() {
        add(&[&shell(), &"--noprofile", &"--norc", &"-i"]);
    } else {
        for arg in spec.command {
            add(&[arg]);
        }
    }
    args
}

fn shell() -> PathBuf {
    ["/usr/bin/bash", "/bin/bash"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("/bin/sh"))
}

pub fn jail_endpoint() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], JAIL_PORT))
}

#[cfg(target_arch = "x86_64")]
const ARCH: (u32, u32) = (0xC000_003E, 16); // AUDIT_ARCH_X86_64, __NR_ioctl
#[cfg(target_arch = "aarch64")]
const ARCH: (u32, u32) = (0xC000_00B7, 29); // AUDIT_ARCH_AARCH64, __NR_ioctl
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("kubejail's seccomp filter only knows x86_64 and aarch64");

/// Seccomp filter that denies the terminal-injection ioctls (TIOCSTI,
/// TIOCLINUX). The jail shares the operator's terminal; without this a
/// jailed process could queue keystrokes that the host shell would run
/// after the session ends.
pub fn seccomp_filter() -> Vec<u8> {
    const LOAD: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const JGE: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
    const RET: u16 = 0x06; // BPF_RET | BPF_K
    const ALLOW: u32 = 0x7fff_0000;
    const KILL_PROCESS: u32 = 0x8000_0000;
    const EPERM: u32 = 0x0005_0000 | 1;
    const TIOCSTI: u32 = 0x5412;
    const TIOCLINUX: u32 = 0x541C;
    let (audit_arch, nr_ioctl) = ARCH;

    // seccomp_data offsets: nr=0, arch=4, args[1]=24 (low 32 bits; the
    // kernel truncates the ioctl request to 32 bits as well).
    let program: [(u16, u8, u8, u32); 11] = [
        (LOAD, 0, 0, 4),
        (JEQ, 1, 0, audit_arch),
        (RET, 0, 0, KILL_PROCESS), // foreign ABI (e.g. int 0x80)
        (LOAD, 0, 0, 0),
        (JGE, 5, 0, 0x4000_0000), // x32 syscall numbers -> EPERM
        (JEQ, 0, 3, nr_ioctl),    // not ioctl -> ALLOW
        (LOAD, 0, 0, 24),
        (JEQ, 2, 0, TIOCSTI),
        (JEQ, 1, 0, TIOCLINUX),
        (RET, 0, 0, ALLOW),
        (RET, 0, 0, EPERM),
    ];
    let mut out = Vec::with_capacity(program.len() * 8);
    for (code, jt, jf, k) in program {
        out.extend_from_slice(&code.to_ne_bytes());
        out.push(jt);
        out.push(jf);
        out.extend_from_slice(&k.to_ne_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(command: &[OsString]) -> Vec<String> {
        bwrap_args(&JailSpec {
            kubeconfig: Path::new("/s/kubeconfig"),
            auth_dir: Path::new("/s/auth"),
            socket: Path::new("/s/api.sock"),
            self_exe: Path::new("/x/kubejail"),
            kubectl: Some(Path::new("/x/kubectl")),
            context: "prod$(id)",
            namespace: "payments",
            term: None,
            seccomp_fd: 7,
            ready_fd: 9,
            command,
        })
        .into_iter()
        .map(|a| a.into_string().unwrap())
        .collect()
    }

    fn has_seq(args: &[String], seq: &[&str]) -> bool {
        args.windows(seq.len()).any(|w| w == seq)
    }

    #[test]
    fn isolates_network_and_environment() {
        let a = args(&[]);
        for flag in ["--unshare-all", "--die-with-parent", "--clearenv"] {
            assert!(a.iter().any(|x| x == flag), "{flag}");
        }
        assert!(!a.iter().any(|x| x == "--share-net"));
        assert!(has_seq(&a, &["--setenv", "HOME", JAIL_HOME]));
        assert!(has_seq(
            &a,
            &["--setenv", "KUBECONFIG", "/home/kubejail/.kube/config"]
        ));
    }

    #[test]
    fn only_binds_system_dirs_and_session_files() {
        let a = args(&[]);
        let mut sources = Vec::new();
        for (i, x) in a.iter().enumerate() {
            if matches!(
                x.as_str(),
                "--bind" | "--ro-bind" | "--ro-bind-try" | "--dev-bind"
            ) {
                assert_ne!(x, "--bind", "nothing from the host is writable");
                assert_ne!(x, "--dev-bind");
                sources.push(a[i + 1].as_str());
            }
        }
        for src in sources {
            let system = [
                "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
            ];
            assert!(
                system.contains(&src)
                    || src.starts_with("/etc/")
                    || src.starts_with("/s/")
                    || src.starts_with("/x/"),
                "unexpected bind source {src}"
            );
            assert!(!["/etc/", "/", "/home", "/run", "/var"].contains(&src));
        }
    }

    #[test]
    fn prompt_shows_context_and_namespace_without_shell_metacharacters() {
        let a = args(&[]);
        assert!(has_seq(&a, &["--setenv", "PS1", "[prod??id?/payments] $ "]));
        assert_eq!(a.last().unwrap(), "-i");
    }

    #[test]
    fn custom_command_goes_after_the_init_separator() {
        let a = args(&["kubectl".into(), "get".into(), "pods".into()]);
        assert!(has_seq(
            &a,
            &[
                "jail-init",
                "--ready-fd",
                "9",
                "--",
                "kubectl",
                "get",
                "pods"
            ]
        ));
    }

    #[test]
    fn seccomp_filter_is_well_formed() {
        let f = seccomp_filter();
        assert_eq!(f.len(), 11 * 8);
        // Every jump lands inside the program.
        for (i, ins) in f.chunks(8).enumerate() {
            let code = u16::from_ne_bytes([ins[0], ins[1]]);
            if code == 0x15 || code == 0x35 {
                assert!(i + 1 + (ins[2] as usize) < 11 && i + 1 + (ins[3] as usize) < 11);
            }
        }
    }
}
