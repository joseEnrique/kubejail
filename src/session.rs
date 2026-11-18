//! `kubejail enter`: host side of a session.

use std::ffi::OsString;
use std::fs::Permissions;
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::signal::unix::{SignalKind, signal};

use crate::auth;
use crate::config::{self, Resolved};
use crate::forward;

pub struct Options {
    pub context: String,
    pub namespace: Option<String>,
    pub kubeconfig: Option<PathBuf>,
    pub command: Vec<OsString>,
}

pub fn enter(opts: Options) -> Result<i32> {
    // Single-threaded on purpose: bwrap's --die-with-parent is tied to the
    // thread that spawns it, and that must be the main thread.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(opts))
}

async fn run(opts: Options) -> Result<i32> {
    let kubeconfig = config::load(opts.kubeconfig.as_deref())?;
    let resolved = config::resolve(&kubeconfig, &opts.context, opts.namespace.as_deref())?;

    // Pin the endpoint now: name resolution happens once, on the host, and
    // the forwarder only ever dials these addresses.
    let endpoint = format!("{}:{}", resolved.host, resolved.port);
    let targets: Arc<[SocketAddr]> =
        tokio::net::lookup_host((resolved.host.as_str(), resolved.port))
            .await
            .with_context(|| format!("cannot resolve API server {endpoint}"))?
            .collect();
    forward::connect_pinned(&targets)
        .await
        .with_context(|| format!("cannot reach API server {endpoint}; not opening a shell"))?;

    // Private per-session directory; removed when `dir` drops, on every
    // return path below.
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let dir = tempfile::Builder::new()
        .prefix("kubejail-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(&base)
        .with_context(|| format!("cannot create a session directory in {}", base.display()))?;

    // Credential plugins run here, on the host; a failure means no shell.
    let auth_dir = dir.path().join("auth");
    std::fs::create_dir(&auth_dir)?;
    std::fs::set_permissions(&auth_dir, Permissions::from_mode(0o700))?;
    if let Some(plugin) = &resolved.exec {
        let token = auth::fetch(plugin)
            .await
            .context("cannot obtain credentials; not opening a shell")?;
        auth::publish(&auth_dir, &token.value)?;
        tokio::spawn(auth::keep_fresh(
            plugin.clone(),
            auth_dir.clone(),
            token.expires,
        ));
    }

    let session = Session {
        resolved: &resolved,
        dir: dir.path(),
        targets,
        command: &opts.command,
    };
    #[cfg(target_os = "linux")]
    let code = linux::launch(session).await?;
    #[cfg(target_os = "macos")]
    let code = crate::macos::launch(session).await?;
    Ok(code)
}

/// What a platform backend needs to open the jail.
pub struct Session<'a> {
    pub resolved: &'a Resolved,
    pub dir: &'a Path,
    pub targets: Arc<[SocketAddr]>,
    /// Empty means "interactive shell".
    pub command: &'a [OsString],
}

/// Wait for the jail to end. SIGTERM/SIGHUP end it early; either way the
/// caller's cleanup runs afterwards.
pub async fn wait(child: &mut tokio::process::Child) -> Result<ExitStatus> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            status = child.wait() => return Ok(status?),
            // The terminal delivers Ctrl-C to the jailed processes as well;
            // the session ends when they do.
            _ = sigint.recv() => {}
            _ = sigterm.recv() => { let _ = child.start_kill(); }
            _ = sighup.recv() => { let _ = child.start_kill(); }
        }
    }
}

pub fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(data))
        .with_context(|| format!("cannot write {}", path.display()))
}

/// The operator's kubectl, wherever their PATH finds it.
pub fn find_kubectl() -> Option<PathBuf> {
    let found = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("kubectl"))
            .find(|p| {
                p.metadata()
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
            .and_then(|p| p.canonicalize().ok())
    });
    if found.is_none() {
        eprintln!("kubejail: warning: kubectl not found in PATH; the jail will not have it");
    }
    found
}

/// `[context/namespace] $ `. The prompt is interpreted by the shell, so
/// anything that is not a plain name character is replaced, not escaped.
pub fn prompt(context: &str, namespace: &str) -> String {
    let safe = |name: &str| -> String {
        name.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "._:@-".contains(c) {
                    c
                } else {
                    '?'
                }
            })
            .collect()
    };
    format!("[{}/{}] $ ", safe(context), safe(namespace))
}

/// Mark every descriptor >= `first` close-on-exec, so nothing inherited
/// leaks into the next program. Only async-signal-safe calls: this runs
/// between fork and exec.
#[cfg(target_os = "linux")]
pub fn cloexec_fds_from(first: u32) -> std::io::Result<()> {
    const CLOSE_RANGE_CLOEXEC: u32 = 4;
    // SAFETY: plain syscall with integer arguments. Fails (aborting the
    // exec) on kernels without close_range(2) rather than leaking.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, CLOSE_RANGE_CLOEXEC) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
pub fn cloexec_fds_from(first: u32) -> std::io::Result<()> {
    // SAFETY: fcntl with integer arguments; EBADF for unused slots is fine.
    unsafe {
        for fd in first as i32..libc::getdtablesize() {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;
    use std::path::Path;

    use anyhow::{Context as _, Result, bail};

    use super::{Session, cloexec_fds_from, exit_code, find_kubectl, wait, write_private};
    use crate::auth;
    use crate::forward;
    use crate::jail::{self, JAIL_PORT, JailSpec};

    /// Bubblewrap jail: own network namespace, reached through a Unix socket.
    pub async fn launch(session: Session<'_>) -> Result<i32> {
        let Session {
            resolved,
            dir,
            targets,
            command,
        } = session;
        let self_exe = std::env::current_exe().context("cannot locate the kubejail binary")?;
        let kubectl = find_kubectl();

        let kubeconfig_path = dir.join("kubeconfig");
        let auth_dir = dir.join("auth");
        let token_file = Path::new(jail::JAIL_AUTH_DIR).join(auth::TOKEN_FILE);
        write_private(
            &kubeconfig_path,
            resolved.jail_kubeconfig(JAIL_PORT, &token_file).as_bytes(),
        )?;
        let seccomp_path = dir.join("seccomp.bpf");
        write_private(&seccomp_path, &jail::seccomp_filter())?;
        let seccomp = File::open(&seccomp_path)?;

        let socket_path = dir.join("api.sock");
        let listener = forward::HostListener::bind(&socket_path)
            .with_context(|| format!("cannot create session socket {}", socket_path.display()))?;
        let forwarder = tokio::spawn(forward::serve_host(listener, targets));

        let (mut ready_rx, ready_tx) = std::io::pipe().context("cannot create readiness pipe")?;
        let (seccomp_fd, ready_fd) = (seccomp.as_raw_fd(), ready_tx.as_raw_fd());

        let bwrap = std::env::var_os("KUBEJAIL_BWRAP").unwrap_or_else(|| "bwrap".into());
        let mut cmd = tokio::process::Command::new(&bwrap);
        cmd.args(jail::bwrap_args(&JailSpec {
            kubeconfig: &kubeconfig_path,
            auth_dir: &auth_dir,
            socket: &socket_path,
            self_exe: &self_exe,
            kubectl: kubectl.as_deref(),
            context: &resolved.context,
            namespace: &resolved.namespace,
            term: std::env::var_os("TERM"),
            seccomp_fd,
            ready_fd,
            command,
        }));
        cmd.kill_on_drop(true);
        // SAFETY: only async-signal-safe calls between fork and exec. Every
        // inherited descriptor above stdio is dropped except the two bwrap
        // needs.
        unsafe {
            cmd.pre_exec(move || {
                cloexec_fds_from(3)?;
                for fd in [seccomp_fd, ready_fd] {
                    if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "cannot start Bubblewrap ({}); not opening a shell",
                bwrap.to_string_lossy()
            )
        })?;
        drop(ready_tx);
        drop(seccomp);

        let status = wait(&mut child).await?;
        forwarder.abort();

        // The jail writes to this pipe only once its forwarder is listening,
        // right before it starts the shell.
        let mut ready = [0u8; 5];
        // SAFETY: fcntl on a descriptor we own.
        unsafe { libc::fcntl(ready_rx.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        if !matches!(ready_rx.read(&mut ready), Ok(5)) {
            bail!("the jail could not be started ({status}); no shell was opened");
        }
        Ok(exit_code(status))
    }
}
