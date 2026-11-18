//! Resolve one context of the operator's kubeconfig into (a) the real API
//! server endpoint and (b) a self-contained kubeconfig for the jail.

use std::path::Path;

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use kube::config::{ExecInteractiveMode, Kubeconfig};
use secrecy::ExposeSecret as _;
use serde_json::json;
use url::{Host, Url};

#[derive(Debug)]
pub struct Resolved {
    pub context: String,
    pub namespace: String,
    /// Host and port of the real API server, as written in the kubeconfig.
    pub host: String,
    pub port: u16,
    /// Path prefix of the server URL, without a trailing slash.
    path: String,
    /// Jail kubeconfig, complete except for the cluster's `server`.
    template: serde_json::Value,
    /// Credential plugin to run on the host, when the user has one.
    pub exec: Option<ExecPlugin>,
}

/// An `exec` credential plugin (EKS, GKE, AKS...). It needs the network and
/// the operator's cloud credentials, so it runs on the host; the jail only
/// ever sees the short-lived token it produces.
#[derive(Debug, Clone)]
pub struct ExecPlugin {
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Value for KUBERNETES_EXEC_INFO.
    pub info: String,
    pub install_hint: Option<String>,
}

impl Resolved {
    /// Kubeconfig (JSON, which is valid YAML) to expose inside the jail,
    /// pointing at the session's loopback port. Same path, different
    /// authority: kubectl still verifies the certificate against the
    /// original name through `tls-server-name`.
    ///
    /// `token_file` is where the jail will find the plugin's token; it is
    /// only used for contexts with a credential plugin.
    pub fn jail_kubeconfig(&self, port: u16, token_file: &Path) -> String {
        let mut config = self.template.clone();
        config["clusters"][0]["cluster"]["server"] =
            format!("https://127.0.0.1:{port}{}", self.path).into();
        if self.exec.is_some() {
            config["users"][0]["user"] = json!({ "tokenFile": token_file });
        }
        serde_json::to_string_pretty(&config).expect("JSON values always serialize")
    }
}

/// Load the kubeconfig the way kubectl does. Relative certificate paths are
/// resolved against the file that declares them (done by `kube::config`).
pub fn load(path: Option<&Path>) -> Result<Kubeconfig> {
    match path {
        Some(path) => {
            let path = std::path::absolute(path)
                .with_context(|| format!("invalid kubeconfig path {}", path.display()))?;
            Kubeconfig::read_from(&path)
                .with_context(|| format!("cannot load kubeconfig {}", path.display()))
        }
        None => Kubeconfig::read().context("cannot load kubeconfig"),
    }
}

pub fn resolve(cfg: &Kubeconfig, context: &str, namespace: Option<&str>) -> Result<Resolved> {
    let ctx = cfg
        .contexts
        .iter()
        .find(|c| c.name == context)
        .and_then(|c| c.context.as_ref())
        .ok_or_else(|| {
            let mut names: Vec<&str> = cfg.contexts.iter().map(|c| c.name.as_str()).collect();
            names.sort_unstable();
            anyhow!(
                "context {context:?} not found in kubeconfig (available: {})",
                if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join(", ")
                }
            )
        })?;

    let cluster = cfg
        .clusters
        .iter()
        .find(|c| c.name == ctx.cluster)
        .and_then(|c| c.cluster.as_ref())
        .ok_or_else(|| anyhow!("cluster {:?} of context {context:?} not found", ctx.cluster))?;
    let user_name = ctx
        .user
        .as_deref()
        .ok_or_else(|| anyhow!("context {context:?} has no user"))?;
    let user = cfg
        .auth_infos
        .iter()
        .find(|u| u.name == user_name)
        .and_then(|u| u.auth_info.as_ref())
        .ok_or_else(|| anyhow!("user {user_name:?} of context {context:?} not found"))?;

    // --- Cluster: direct HTTPS endpoints with verified TLS only. ---
    if cluster.proxy_url.is_some() {
        bail!(
            "cluster {:?} uses proxy-url; proxied clusters are not supported",
            ctx.cluster
        );
    }
    if cluster.insecure_skip_tls_verify == Some(true) {
        bail!(
            "cluster {:?} sets insecure-skip-tls-verify; unverified TLS is not supported",
            ctx.cluster
        );
    }
    let server = cluster
        .server
        .as_deref()
        .ok_or_else(|| anyhow!("cluster {:?} has no server", ctx.cluster))?;
    let url = Url::parse(server).with_context(|| format!("invalid server URL {server:?}"))?;
    if url.scheme() != "https" {
        bail!("server {server:?} is not an https:// endpoint; only direct HTTPS is supported");
    }
    let host = match url.host() {
        Some(Host::Domain(d)) => d.to_string(),
        Some(Host::Ipv4(ip)) => ip.to_string(),
        Some(Host::Ipv6(ip)) => ip.to_string(),
        None => bail!("server {server:?} has no host"),
    };
    let port = url.port().unwrap_or(443);

    // --- User: client certificates, or a credential plugin run on the host. ---
    if user.auth_provider.is_some() {
        bail!("user {user_name:?} uses an auth-provider; not supported yet");
    }
    if user.token.is_some()
        || user.token_file.is_some()
        || user.username.is_some()
        || user.password.is_some()
    {
        bail!(
            "user {user_name:?} uses a static token or basic authentication; only client certificates and exec credential plugins are supported"
        );
    }
    if user.impersonate.is_some() || user.impersonate_groups.is_some() {
        bail!("user {user_name:?} uses impersonation; not supported yet");
    }
    let ca = pem_data(
        cluster.certificate_authority_data.as_deref(),
        cluster.certificate_authority.as_deref(),
        "certificate authority",
    )?;
    let (jail_user, exec) = if let Some(exec) = &user.exec {
        if matches!(exec.interactive_mode, Some(ExecInteractiveMode::Always)) {
            bail!("user {user_name:?} needs an interactive credential plugin; not supported");
        }
        let command = exec
            .command
            .clone()
            .ok_or_else(|| anyhow!("user {user_name:?} has an exec plugin without a command"))?;
        let api_version = exec
            .api_version
            .clone()
            .unwrap_or_else(|| "client.authentication.k8s.io/v1".to_string());
        let mut spec = json!({ "interactive": false });
        if exec.provide_cluster_info {
            spec["cluster"] = json!({ "server": server, "certificate-authority-data": ca });
        }
        let env = exec
            .env
            .iter()
            .flatten()
            .filter_map(|e| Some((e.get("name")?.clone(), e.get("value")?.clone())))
            .collect();
        let plugin = ExecPlugin {
            command,
            args: exec.args.clone().unwrap_or_default(),
            env,
            info: json!({ "apiVersion": api_version, "kind": "ExecCredential", "spec": spec })
                .to_string(),
            install_hint: exec.install_hint.clone(),
        };
        // The token file path is filled in by `jail_kubeconfig`.
        (json!({}), Some(plugin))
    } else {
        let client_cert = pem_data(
            user.client_certificate_data.as_deref(),
            user.client_certificate.as_deref(),
            "client certificate",
        )?
        .ok_or_else(|| {
            anyhow!(
                "user {user_name:?} has neither a client certificate nor an exec credential plugin"
            )
        })?;
        let client_key = pem_data(
            user.client_key_data.as_ref().map(|s| s.expose_secret()),
            user.client_key.as_deref(),
            "client key",
        )?
        .ok_or_else(|| anyhow!("user {user_name:?} has a client certificate but no client key"))?;
        let user = json!({
            "client-certificate-data": client_cert,
            "client-key-data": client_key,
        });
        (user, None)
    };

    let namespace = namespace
        .map(str::to_owned)
        .or_else(|| ctx.namespace.clone())
        .unwrap_or_else(|| "default".to_string());

    let tls_server_name = cluster.tls_server_name.clone().unwrap_or(host.clone());
    let mut jail_cluster = json!({ "tls-server-name": tls_server_name });
    if let Some(ca) = ca {
        jail_cluster["certificate-authority-data"] = ca.into();
    }
    let template = json!({
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": context,
        "clusters": [{ "name": ctx.cluster, "cluster": jail_cluster }],
        "users": [{ "name": user_name, "user": jail_user }],
        "contexts": [{ "name": context, "context": {
            "cluster": ctx.cluster,
            "user": user_name,
            "namespace": namespace,
        }}],
    });

    Ok(Resolved {
        context: context.to_string(),
        namespace,
        host,
        port,
        path: url.path().trim_end_matches('/').to_string(),
        template,
        exec,
    })
}

/// Return base64 PEM from inline data (preferred, like kubectl) or a file.
fn pem_data(inline: Option<&str>, file: Option<&str>, what: &str) -> Result<Option<String>> {
    let (bytes, origin) = if let Some(data) = inline {
        let bytes = BASE64
            .decode(data.trim())
            .with_context(|| format!("{what} data is not valid base64"))?;
        (bytes, "inline data".to_string())
    } else if let Some(path) = file {
        let bytes = std::fs::read(path).with_context(|| format!("cannot read {what} {path}"))?;
        (bytes, path.to_string())
    } else {
        return Ok(None);
    };
    if !bytes.windows(10).any(|w| w == b"-----BEGIN") {
        bail!("{what} ({origin}) is not PEM encoded");
    }
    Ok(Some(BASE64.encode(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    fn b64(s: &str) -> String {
        BASE64.encode(s)
    }

    fn kubeconfig(cluster_extra: &str, user: &str) -> Kubeconfig {
        let yaml = format!(
            r#"
apiVersion: v1
kind: Config
current-context: other
clusters:
- name: c-a
  cluster:
    server: https://api.a.example:8443
    certificate-authority-data: {ca}
{cluster_extra}
- name: c-b
  cluster:
    server: https://api.b.example
users:
- name: u-a
  user:
{user}
- name: u-b
  user:
    token: secret-b
contexts:
- name: a
  context: {{cluster: c-a, user: u-a, namespace: team}}
- name: other
  context: {{cluster: c-b, user: u-b}}
"#,
            ca = b64(PEM),
        );
        Kubeconfig::from_yaml(&yaml).unwrap()
    }

    fn cert_user() -> String {
        format!(
            "    client-certificate-data: {}\n    client-key-data: {}",
            b64(PEM),
            b64("-----BEGIN PRIVATE KEY-----\nBBBB\n")
        )
    }

    fn err(cfg: &Kubeconfig, context: &str) -> String {
        format!("{:#}", resolve(cfg, context, None).unwrap_err())
    }

    #[test]
    fn generates_single_context_config_pointing_at_loopback() {
        let cfg = kubeconfig("", &cert_user());
        let r = resolve(&cfg, "a", None).unwrap();
        assert_eq!((r.host.as_str(), r.port), ("api.a.example", 8443));
        assert_eq!(r.namespace, "team");

        let out: Value =
            serde_json::from_str(&r.jail_kubeconfig(6443, Path::new("/t/token"))).unwrap();
        assert_eq!(out["current-context"], "a");
        for list in ["clusters", "users", "contexts"] {
            assert_eq!(out[list].as_array().unwrap().len(), 1, "{list}");
        }
        let cluster = &out["clusters"][0]["cluster"];
        assert_eq!(cluster["server"], "https://127.0.0.1:6443");
        assert_eq!(cluster["tls-server-name"], "api.a.example");
        assert_eq!(cluster["certificate-authority-data"], b64(PEM));
        assert_eq!(out["users"][0]["user"]["client-certificate-data"], b64(PEM));
        assert_eq!(out["contexts"][0]["context"]["namespace"], "team");
        // Nothing about the other cluster or its credentials leaks in.
        assert!(
            !r.jail_kubeconfig(6443, Path::new("/t/token"))
                .contains("secret-b")
        );
        assert!(
            !r.jail_kubeconfig(6443, Path::new("/t/token"))
                .contains("api.b.example")
        );
    }

    #[test]
    fn namespace_flag_overrides_context_and_tls_name_is_kept() {
        let cfg = kubeconfig("    tls-server-name: kube.internal", &cert_user());
        let r = resolve(&cfg, "a", Some("payments")).unwrap();
        assert_eq!(r.namespace, "payments");
        let out: Value =
            serde_json::from_str(&r.jail_kubeconfig(6443, Path::new("/t/token"))).unwrap();
        assert_eq!(
            out["clusters"][0]["cluster"]["tls-server-name"],
            "kube.internal"
        );
        assert_eq!(out["contexts"][0]["context"]["namespace"], "payments");
    }

    #[test]
    fn unknown_context_lists_the_available_ones() {
        let cfg = kubeconfig("", &cert_user());
        let msg = err(&cfg, "nope");
        assert!(
            msg.contains("not found") && msg.contains("a, other"),
            "{msg}"
        );
    }

    #[test]
    fn rejects_unsupported_configurations() {
        let cases = [
            ("    proxy-url: http://proxy:3128", cert_user(), "proxy"),
            (
                "    insecure-skip-tls-verify: true",
                cert_user(),
                "insecure-skip-tls-verify",
            ),
            (
                "",
                "    exec: {command: login, interactiveMode: Always}".to_string(),
                "interactive credential plugin",
            ),
            ("", "    token: abc".to_string(), "static token"),
            ("", "    username: admin".to_string(), "static token"),
            ("", "    as: someone-else".to_string(), "impersonation"),
        ];
        for (cluster_extra, user, expected) in cases {
            let msg = err(&kubeconfig(cluster_extra, &user), "a");
            assert!(msg.contains(expected), "expected {expected:?} in {msg:?}");
        }
    }

    #[test]
    fn exec_plugin_runs_on_the_host_and_the_jail_gets_a_token_file() {
        let user = r#"    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args: [eks, get-token, --cluster-name, demo]
      env: [{name: AWS_PROFILE, value: ops}]
      provideClusterInfo: true"#;
        let r = resolve(&kubeconfig("", user), "a", None).unwrap();
        let plugin = r.exec.as_ref().unwrap();
        assert_eq!(plugin.command, "aws");
        assert_eq!(plugin.args, ["eks", "get-token", "--cluster-name", "demo"]);
        assert_eq!(plugin.env, [("AWS_PROFILE".to_string(), "ops".to_string())]);
        let info: Value = serde_json::from_str(&plugin.info).unwrap();
        assert_eq!(info["apiVersion"], "client.authentication.k8s.io/v1beta1");
        assert_eq!(info["spec"]["interactive"], false);
        assert_eq!(
            info["spec"]["cluster"]["server"],
            "https://api.a.example:8443"
        );

        // Nothing about the plugin reaches the jail, only the token's path.
        let jailed = r.jail_kubeconfig(6443, Path::new("/t/token"));
        let out: Value = serde_json::from_str(&jailed).unwrap();
        assert_eq!(out["users"][0]["user"], json!({ "tokenFile": "/t/token" }));
        assert!(!jailed.contains("aws") && !jailed.contains("AWS_PROFILE"));
    }

    #[test]
    fn rejects_plain_http() {
        let mut cfg = kubeconfig("", &cert_user());
        cfg.clusters[0].cluster.as_mut().unwrap().server = Some("http://api.a.example".into());
        assert!(err(&cfg, "a").contains("https"));
    }

    #[test]
    fn resolves_certificate_files_relative_to_the_kubeconfig() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("pki")).unwrap();
        std::fs::write(
            dir.path().join("pki/ca.crt"),
            "-----BEGIN CERTIFICATE-----\nCA\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("pki/c.crt"),
            "-----BEGIN CERTIFICATE-----\nCRT\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("pki/c.key"),
            "-----BEGIN PRIVATE KEY-----\nKEY\n",
        )
        .unwrap();
        let path = dir.path().join("config.yaml");
        let original = r#"
apiVersion: v1
kind: Config
clusters:
- name: c
  cluster: {server: "https://[::1]:6443/prefix/", certificate-authority: pki/ca.crt}
users:
- name: u
  user: {client-certificate: pki/c.crt, client-key: pki/c.key}
contexts:
- name: ctx
  context: {cluster: c, user: u}
"#;
        std::fs::write(&path, original).unwrap();

        let r = resolve(&load(Some(&path)).unwrap(), "ctx", None).unwrap();
        assert_eq!((r.host.as_str(), r.port), ("::1", 6443));
        assert_eq!(r.namespace, "default");
        let out: Value =
            serde_json::from_str(&r.jail_kubeconfig(6443, Path::new("/t/token"))).unwrap();
        let cluster = &out["clusters"][0]["cluster"];
        assert_eq!(cluster["server"], "https://127.0.0.1:6443/prefix");
        assert_eq!(cluster["tls-server-name"], "::1");
        assert_eq!(
            cluster["certificate-authority-data"],
            b64("-----BEGIN CERTIFICATE-----\nCA\n")
        );
        let user = &out["users"][0]["user"];
        assert_eq!(
            user["client-certificate-data"],
            b64("-----BEGIN CERTIFICATE-----\nCRT\n")
        );
        assert_eq!(
            user["client-key-data"],
            b64("-----BEGIN PRIVATE KEY-----\nKEY\n")
        );
        // The source file is only ever read.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn missing_certificate_file_is_a_clear_error() {
        let mut cfg = kubeconfig("", &cert_user());
        let user = cfg.auth_infos[0].auth_info.as_mut().unwrap();
        user.client_certificate_data = None;
        user.client_certificate = Some("/nonexistent/client.crt".into());
        assert!(err(&cfg, "a").contains("/nonexistent/client.crt"));
    }
}
