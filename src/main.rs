//! kubejail: open a shell whose only direct network route is the API server
//! of one Kubernetes cluster, chosen when the session starts.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("kubejail supports Linux (Bubblewrap) and macOS (sandbox-exec) only");

mod auth;
mod config;
mod forward;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod jail;
#[cfg(any(target_os = "macos", test))]
mod macos;
mod session;

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kubejail", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Open a shell that can only reach the API server of one context
    Enter {
        /// Context name, as listed by `kubectl config get-contexts`
        context: String,
        /// Default namespace for the session (defaults to the context's own)
        #[arg(short = 'n', long)]
        namespace: Option<String>,
        /// Load this kubeconfig instead of $KUBECONFIG / ~/.kube/config
        #[arg(long, value_name = "PATH")]
        kubeconfig: Option<PathBuf>,
        /// Run this command inside the jail instead of an interactive shell
        #[arg(last = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
    /// Internal: runs inside the jail, starts the loopback forwarder and the shell
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    JailInit {
        #[arg(long)]
        ready_fd: Option<i32>,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
}

fn main() {
    let result = match Cli::parse().command {
        Command::Enter {
            context,
            namespace,
            kubeconfig,
            command,
        } => session::enter(session::Options {
            context,
            namespace,
            kubeconfig,
            command,
        }),
        #[cfg(target_os = "linux")]
        Command::JailInit { ready_fd, command } => init::run(ready_fd, command),
    };
    // Everything owned by the session (temp dir, socket, child) has been
    // dropped by the time we get here, so exiting does not skip cleanup.
    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("kubejail: error: {err:#}");
            std::process::exit(1);
        }
    }
}
