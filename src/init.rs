//! `kubejail jail-init`: first process inside the jail. Starts the loopback
//! forwarder, reports readiness to the host, then runs the shell.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::FromRawFd as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use tokio::net::{TcpListener, UnixStream};

use crate::forward;
use crate::jail::{JAIL_SOCKET, jail_endpoint};
use crate::session::cloexec_fds_from;

pub fn run(ready_fd: Option<i32>, command: Vec<OsString>) -> Result<i32> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let addr = jail_endpoint();
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("cannot listen on {addr} inside the jail"))?;
        // Prove the session socket is reachable before any shell exists.
        UnixStream::connect(JAIL_SOCKET)
            .await
            .with_context(|| format!("cannot reach the session socket {JAIL_SOCKET}"))?;
        tokio::spawn(forward::serve_jail(listener, PathBuf::from(JAIL_SOCKET)));

        if let Some(fd) = ready_fd {
            // SAFETY: the host passes this pipe to us and nothing else in
            // this process owns it; it is closed when `pipe` drops.
            let mut pipe = unsafe { File::from_raw_fd(fd) };
            pipe.write_all(b"ready")
                .context("cannot report readiness to the host")?;
        }

        let (program, args) = command.split_first().context("no command to run")?;
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args);
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe { cmd.pre_exec(|| cloexec_fds_from(3)) };
        let mut child = cmd
            .spawn()
            .with_context(|| format!("cannot run {}", program.to_string_lossy()))?;
        let status = child.wait().await?;
        Ok(status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
    })
}
