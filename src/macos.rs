//! macOS backend: the system sandbox (Seatbelt, via `sandbox-exec`).
//!
//! macOS has no network namespaces, so the jail shares the host's network
//! stack and a sandbox profile denies every network operation except
//! connecting to the session's forwarder port on loopback.

use std::path::Path;

use anyhow::{Result, anyhow};

/// Mach services the jailed tools may look up: user-name lookups, logging
/// and certificate trust evaluation. Everything else (launchd,
/// LaunchServices, Apple Events...) is denied, so a jailed process cannot
/// ask an unsandboxed one to act for it.
const MACH_ALLOWLIST: &[&str] = &[
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.notification_center",
    "com.apple.system.logger",
    "com.apple.logd",
    "com.apple.trustd",
    "com.apple.trustd.agent",
];

/// Seatbelt profile for one session. Later rules win over earlier ones.
/// `session` must be a canonical path (Seatbelt matches resolved paths).
pub fn sandbox_profile(session: &Path, port: u16) -> Result<String> {
    let quote = |path: &Path| -> Result<String> {
        let text = path
            .to_str()
            .ok_or_else(|| anyhow!("session path {} is not UTF-8", path.display()))?;
        Ok(format!(
            "\"{}\"",
            text.replace('\\', "\\\\").replace('"', "\\\"")
        ))
    };
    let home = quote(&session.join("home"))?;
    let bin = quote(&session.join("bin"))?;
    let auth = quote(&session.join("auth"))?;
    // The shell must be able to stat the directories leading to its HOME.
    let mut ancestors = String::new();
    for dir in session.ancestors().filter(|d| *d != Path::new("/")) {
        ancestors.push_str(&format!(" (literal {})", quote(dir)?));
    }
    let mach: String = MACH_ALLOWLIST
        .iter()
        .map(|name| format!(" (global-name \"{name}\")"))
        .collect();

    Ok(format!(
        r#"(version 1)
(allow default)

;; Network: nothing but the session's forwarder on loopback. This also
;; covers Unix sockets, so no host daemon is reachable either.
(deny network*)
(allow network-outbound (remote ip "localhost:{port}"))

;; Files: the system is read-only; home directories, other volumes and
;; other temporary files are not readable at all.
(deny file-write*)
(deny file-read*
  (subpath "/Users") (subpath "/Volumes") (subpath "/private/var/root")
  (subpath "/private/tmp") (subpath "/private/var/folders")
  (subpath "/Library/Keychains"))
(allow file-read-metadata{ancestors})
(allow file-read* file-write* (subpath {home}))
(allow file-read* (subpath {bin}) (subpath {auth}))
(allow file-write*
  (literal "/dev/null") (literal "/dev/tty") (literal "/dev/dtracehelper")
  (regex #"^/dev/ttys[0-9]+$") (regex #"^/dev/fd/[0-9]+$"))

;; No asking unsandboxed processes to act on the jail's behalf.
(deny mach-lookup)
(allow mach-lookup{mach})
"#
    ))
}

#[cfg(target_os = "macos")]
pub async fn launch(session: crate::session::Session<'_>) -> Result<i32> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt as _;

    use anyhow::{Context as _, bail};
    use tokio::process::Command;

    use crate::forward;
    use crate::session::{
        Session, cloexec_fds_from, exit_code, find_kubectl, prompt, wait, write_private,
    };

    let Session {
        resolved,
        dir,
        targets,
        command,
    } = session;
    let dir = dir
        .canonicalize()
        .context("cannot resolve the session directory")?;

    let listener = forward::HostListener::bind("127.0.0.1:0")
        .await
        .context("cannot open the session's loopback port")?;
    let port = listener.local_addr()?.port();
    let forwarder = tokio::spawn(forward::serve_host(listener, targets));

    let (home, bin) = (dir.join("home"), dir.join("bin"));
    for path in [&home, &home.join(".kube"), &home.join("tmp"), &bin] {
        std::fs::create_dir(path)?;
        std::fs::set_permissions(path, Permissions::from_mode(0o700))?;
    }
    let kubeconfig_path = home.join(".kube/config");
    let token_file = dir.join("auth").join(crate::auth::TOKEN_FILE);
    write_private(
        &kubeconfig_path,
        resolved.jail_kubeconfig(port, &token_file).as_bytes(),
    )?;
    // The operator's kubectl may live under /Users, which the jail cannot
    // read, so the session gets its own (copy-on-write on APFS) copy.
    if let Some(kubectl) = find_kubectl() {
        std::fs::copy(&kubectl, bin.join("kubectl"))
            .with_context(|| format!("cannot copy {} into the session", kubectl.display()))?;
        // The usual shorthand; the operator's shell aliases do not exist here.
        std::os::unix::fs::symlink("kubectl", bin.join("k"))?;
    }
    let profile_path = dir.join("profile.sb");
    write_private(&profile_path, sandbox_profile(&dir, port)?.as_bytes())?;

    let sandbox_exec =
        std::env::var_os("KUBEJAIL_SANDBOX_EXEC").unwrap_or_else(|| "/usr/bin/sandbox-exec".into());
    let jailed = |program: &dyn AsRef<std::ffi::OsStr>| {
        let mut cmd = Command::new(&sandbox_exec);
        cmd.arg("-f").arg(&profile_path).arg(program);
        cmd.env_clear()
            .env("HOME", &home)
            .env("TMPDIR", home.join("tmp"))
            .env(
                "PATH",
                format!(
                    "{}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                    bin.display()
                ),
            )
            .env("KUBECONFIG", &kubeconfig_path)
            .env("PS1", prompt(&resolved.context))
            .env("KUBEJAIL_CONTEXT", &resolved.context)
            .env("KUBEJAIL_NAMESPACE", &resolved.namespace)
            .env("LANG", "en_US.UTF-8")
            .env("BASH_SILENCE_DEPRECATION_WARNING", "1")
            .current_dir(&home)
            .kill_on_drop(true);
        if let Some(term) = std::env::var_os("TERM") {
            cmd.env("TERM", term);
        }
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe { cmd.pre_exec(|| cloexec_fds_from(3)) };
        cmd
    };

    // Prove the sandbox can be applied before any shell exists.
    let probe = jailed(&"/usr/bin/true")
        .stdin(std::process::Stdio::null())
        .status()
        .await;
    if !probe.as_ref().is_ok_and(|status| status.success()) {
        bail!(
            "cannot apply the macOS sandbox with {} ({}); no shell was opened",
            sandbox_exec.to_string_lossy(),
            match probe {
                Ok(status) => status.to_string(),
                Err(err) => err.to_string(),
            }
        );
    }

    let mut cmd = match command.split_first() {
        Some((program, args)) => {
            let mut cmd = jailed(program);
            cmd.args(args);
            cmd
        }
        None => {
            let mut cmd = jailed(&"/bin/bash");
            cmd.args(["--noprofile", "--norc", "-i"]);
            cmd
        }
    };
    let mut child = cmd
        .spawn()
        .context("cannot start the sandboxed shell; no shell was opened")?;
    let status = wait(&mut child).await?;
    forwarder.abort();
    Ok(exit_code(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> String {
        sandbox_profile(Path::new("/private/var/folders/ab/T/kubejail-x\"y"), 51234).unwrap()
    }

    #[test]
    fn network_is_denied_except_the_session_port() {
        let p = profile();
        let deny = p.find("(deny network*)").unwrap();
        let allow = p
            .find("(allow network-outbound (remote ip \"localhost:51234\"))")
            .unwrap();
        // Later rules win, so the single exception must follow the denial.
        assert!(deny < allow);
        assert_eq!(p.matches("network").count(), 2);
    }

    #[test]
    fn only_the_session_home_is_writable() {
        let p = profile();
        let deny = p.find("(deny file-write*)").unwrap();
        let home = p
            .find("(allow file-read* file-write* (subpath \"/private/var/folders/ab/T/kubejail-x\\\"y/home\"))")
            .unwrap();
        assert!(deny < home);
        assert!(p.contains("(subpath \"/Users\")"));
        assert!(p.contains("(literal \"/private/var/folders/ab/T\")"));
        assert!(!p.contains("(literal \"/\")"));
    }

    #[test]
    fn parentheses_are_balanced() {
        let p = profile();
        assert_eq!(p.matches('(').count(), p.matches(')').count());
    }
}
