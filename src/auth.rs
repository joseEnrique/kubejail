//! Credential plugins (`exec` users: EKS, GKE, AKS...).
//!
//! The plugin runs on the host, where the operator's cloud credentials and
//! the network are. The jail only gets the resulting short-lived token, as a
//! file that is replaced before the token expires.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use jiff::Timestamp;

use crate::config::ExecPlugin;
use crate::session::write_private;

pub const TOKEN_FILE: &str = "token";

pub struct Token {
    pub value: String,
    pub expires: Option<Timestamp>,
}

/// Run the plugin once and parse its ExecCredential.
pub async fn fetch(plugin: &ExecPlugin) -> Result<Token> {
    let output = tokio::process::Command::new(&plugin.command)
        .args(&plugin.args)
        .envs(plugin.env.iter().map(|(k, v)| (k, v)))
        .env("KUBERNETES_EXEC_INFO", &plugin.info)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // The plugin's own messages (expired SSO session...) go to the operator.
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "cannot run credential plugin {:?}{}",
                plugin.command,
                plugin
                    .install_hint
                    .as_ref()
                    .map(|hint| format!(" ({hint})"))
                    .unwrap_or_default()
            )
        })?
        .wait_with_output()
        .await?;
    if !output.status.success() {
        bail!(
            "credential plugin {:?} failed ({})",
            plugin.command,
            output.status
        );
    }
    let credential: serde_json::Value =
        serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "credential plugin {:?} printed invalid JSON",
                plugin.command
            )
        })?;
    let status = &credential["status"];
    let value = status["token"].as_str().ok_or_else(|| {
        anyhow!(
            "credential plugin {:?} returned no token (certificate-based plugins are not supported)",
            plugin.command
        )
    })?;
    let expires = match status["expirationTimestamp"].as_str() {
        Some(text) => Some(text.parse::<Timestamp>().with_context(|| {
            format!(
                "credential plugin {:?} returned an invalid expiry",
                plugin.command
            )
        })?),
        None => None,
    };
    Ok(Token {
        value: value.to_string(),
        expires,
    })
}

/// Publish the token atomically: readers see the old or the new one, never
/// a partial file.
pub fn publish(dir: &Path, token: &str) -> Result<()> {
    let tmp = dir.join(".token.new");
    let _ = std::fs::remove_file(&tmp);
    write_private(&tmp, token.as_bytes())?;
    std::fs::rename(&tmp, dir.join(TOKEN_FILE)).context("cannot publish the session token")
}

/// How long to wait before replacing a token: a minute before it expires,
/// or halfway through a short-lived one.
fn refresh_delay(expires: Timestamp, now: Timestamp) -> Duration {
    let remaining = expires.as_second() - now.as_second();
    Duration::from_secs((remaining - 60).max(remaining / 2).max(2) as u64)
}

/// Keep the published token fresh for as long as the session lives.
pub async fn keep_fresh(plugin: ExecPlugin, dir: PathBuf, mut expires: Option<Timestamp>) {
    // Tokens without an expiry are valid until the plugin says otherwise.
    while let Some(at) = expires {
        tokio::time::sleep(refresh_delay(at, Timestamp::now())).await;
        match fetch(&plugin).await.and_then(|token| {
            publish(&dir, &token.value)?;
            Ok(token.expires)
        }) {
            Ok(next) => expires = next,
            Err(err) => {
                eprintln!("kubejail: warning: cannot refresh the session token: {err:#}");
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(script: &str) -> ExecPlugin {
        ExecPlugin {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![("PLUGIN_TOKEN".into(), "tok-123".into())],
            info: "{}".into(),
            install_hint: None,
        }
    }

    #[tokio::test]
    async fn parses_token_and_expiry() {
        let token = fetch(&plugin(
            r#"echo "{\"status\": {\"token\": \"$PLUGIN_TOKEN\", \"expirationTimestamp\": \"2030-01-02T03:04:05Z\"}}""#,
        ))
        .await
        .unwrap();
        assert_eq!(token.value, "tok-123");
        assert_eq!(token.expires.unwrap().to_string(), "2030-01-02T03:04:05Z");
    }

    #[tokio::test]
    async fn plugin_failures_are_errors() {
        for (script, expected) in [
            ("exit 3", "failed"),
            ("echo not-json", "invalid JSON"),
            (
                r#"echo '{"status": {"clientCertificateData": "x"}}'"#,
                "no token",
            ),
        ] {
            let err = fetch(&plugin(script)).await.err().unwrap();
            assert!(format!("{err:#}").contains(expected), "{err:#}");
        }
    }

    #[test]
    fn refreshes_before_expiry() {
        let now: Timestamp = "2030-01-01T00:00:00Z".parse().unwrap();
        let at = |s: &str| refresh_delay(s.parse().unwrap(), now).as_secs();
        assert_eq!(at("2030-01-01T00:14:00Z"), 13 * 60); // EKS-style 14 minutes
        assert_eq!(at("2030-01-01T00:00:10Z"), 5); // short-lived: halfway
        assert_eq!(at("2029-12-31T23:00:00Z"), 2); // already expired: retry soon
    }

    #[test]
    fn publish_replaces_the_token() {
        let dir = tempfile::tempdir().unwrap();
        publish(dir.path(), "one").unwrap();
        publish(dir.path(), "two").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join(TOKEN_FILE)).unwrap(),
            "two"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
