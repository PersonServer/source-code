//! Configuration: a JSON file plus environment overrides.
//!
//! Kept to JSON deliberately (serde_json is already a dependency; no TOML
//! parser needed). `psd example-config` prints a starting point. Every struct
//! is `deny_unknown_fields` so a typo in the file is a hard error at load,
//! not a silently ignored setting.
//!
//! Merge order is fixed: file → environment → `validate()`. The environment
//! wins over the file so a secret or a hostname can be injected by the
//! deployment without editing the file.

use serde::{Deserialize, Serialize};

/// Person tokens and auth tokens MUST NOT live longer than one hour
/// (AAuth -11 §Person Token Structure, §Auth Token Structure).
pub const MAX_TOKEN_TTL_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The PS's server identifier, e.g. "https://ps.example". PERMANENT: it
    /// lands in every `sub` this server derives and in `iss` of every token it
    /// signs. This exact URL must serve /.well-known/aauth-person.json.
    pub issuer: String,

    /// Listen address, e.g. "127.0.0.1:8430" or "0.0.0.0:8430".
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Path to the signing keys + pairwise-secret file (see `psd keygen`).
    #[serde(default = "default_keys_file")]
    pub keys_file: String,

    #[serde(default)]
    pub storage: StorageConfig,

    /// Person token lifetime in seconds (spec maximum 3600; default 1h). The
    /// issued `exp` is further capped by the presenting agent token's `exp`
    /// and, under a mission, by the mission's `expires_at`.
    #[serde(default = "default_token_ttl")]
    pub person_token_ttl_secs: u64,

    /// Auth token lifetime in seconds (spec maximum 3600; default 1h).
    #[serde(default = "default_token_ttl")]
    pub auth_token_ttl_secs: u64,

    /// HTTP signature `created` validity window, seconds (default 60).
    #[serde(default = "default_signature_window")]
    pub signature_window_secs: u64,

    /// The longest resource-token lifetime (`exp - iat`) this PS accepts at
    /// its auth token endpoint (default 300 — the spec's SHOULD NOT exceed).
    /// This is also the retention floor: person-token records are kept for
    /// at least this long past their `exp`.
    #[serde(default = "default_resource_token_max_age")]
    pub resource_token_max_age_secs: u64,

    /// Extra time person-token records are retained beyond the floor, for
    /// clock skew and operational slack (default 3600).
    /// `purge_after = exp + resource_token_max_age_secs + retention_slack_secs`.
    #[serde(default = "default_retention_slack")]
    pub retention_slack_secs: u64,

    #[serde(default)]
    pub directed_sub: DirectedSubConfig,

    #[serde(default)]
    pub person_auth: PersonAuthConfig,

    #[serde(default)]
    pub notify: NotifyConfig,

    #[serde(default)]
    pub missions: MissionsConfig,

    #[serde(default)]
    pub federation: FederationConfig,

    #[serde(default)]
    pub limits: LimitsConfig,

    #[serde(default)]
    pub ui: UiConfig,

    #[serde(default)]
    pub metadata: MetadataConfig,

    #[serde(default)]
    pub telemetry: TelemetryConfig,

    /// The `@authority` (`Host`) inbound signed requests must carry. Defaults
    /// to the issuer's host. Set it only when a TLS-terminating proxy rewrites
    /// `Host` (better: configure the proxy to preserve it) — the check is what
    /// makes the mandated `@authority` component prevent cross-host replay,
    /// so it is never simply off.
    #[serde(default)]
    pub expected_authority: Option<String>,

    /// DEVELOPMENT ONLY. Accepts an http:// issuer (and ports), allows
    /// outbound fetches over http and to private/loopback addresses, and
    /// permits a non-Secure session cookie. Never enable in production.
    #[serde(default)]
    pub insecure_dev_mode: bool,

    /// Maximum request body size in bytes.
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,

    /// Hosts explicitly admitted as cross-origin JWKS hosts when verifying
    /// foreign tokens: an issuer's metadata may point `jwks_uri` at a
    /// different host than its issuer (e.g. a CDN). Empty (default) means
    /// same-origin JWKS only, per the Signature-Key draft. Bare hostnames.
    #[serde(default)]
    pub jwks_cross_origin_hosts: Vec<String>,

    /// Append structured JSON audit events to this file, in addition to stderr.
    #[serde(default)]
    pub audit_log_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// "sqlite" (default). "postgres" is planned and rejected until it exists,
    /// so a deployment cannot believe it is using it.
    #[serde(default = "default_backend")]
    pub backend: String,
    /// SQLite database path. ":memory:" is accepted for tests and throwaway
    /// runs (state is lost at exit).
    #[serde(default = "default_db_path")]
    pub path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            backend: default_backend(),
            path: default_db_path(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectedSubConfig {
    /// "pairwise" (default and only mode): `sub` is derived per (person,
    /// audience) with the pairwise secret, so two resources cannot correlate.
    #[serde(default = "default_pairwise")]
    pub mode: String,
}

impl Default for DirectedSubConfig {
    fn default() -> Self {
        DirectedSubConfig {
            mode: default_pairwise(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonAuthConfig {
    /// "passkey" (default and only method in this build). "oidc" is planned
    /// for organisation deployments.
    #[serde(default = "default_passkey")]
    pub method: String,
}

impl Default for PersonAuthConfig {
    fn default() -> Self {
        PersonAuthConfig {
            method: default_passkey(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    /// How the person is reached when a decision is pending. "web" (default):
    /// the decision waits on the dashboard. "webhook": additionally POST a
    /// notification to `webhook_url`.
    #[serde(default = "default_channels")]
    pub channels: Vec<String>,
    #[serde(default)]
    pub webhook_url: Option<String>,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        NotifyConfig {
            channels: default_channels(),
            webhook_url: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissionsConfig {
    /// Advertise and serve `mission_endpoint`. Off by default: presence of the
    /// endpoint in metadata is how a PS says it supports missions.
    #[serde(default)]
    pub enabled: bool,
    /// Default lifetime offered on the mission approval screen, seconds
    /// (default 24 h). The person may choose a shorter or longer one, or none.
    #[serde(default = "default_mission_ttl")]
    pub default_ttl_secs: u64,
}

fn default_mission_ttl() -> u64 {
    86_400
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationConfig {
    /// Four-party: when a resource token's `aud` names an Access Server,
    /// obtain the person's consent and then federate to it. Off by default;
    /// exercised against a mock AS only, since no live one exists yet.
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Distinct `resource` values one agent may obtain person tokens for per
    /// rolling day (spec SHOULD rate-limit: each obliges a derived and
    /// retained directed `sub`).
    #[serde(default = "default_resources_per_agent_per_day")]
    pub resources_per_agent_per_day: u32,
    /// Failed interaction-code presentations before the pending interaction
    /// is terminally failed (spec MUST rate-limit code validation).
    #[serde(default = "default_code_attempts")]
    pub code_attempts: u32,
    /// How long a pending (deferred) request waits for the person, seconds.
    #[serde(default = "default_pending_ttl")]
    pub pending_ttl_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            resources_per_agent_per_day: default_resources_per_agent_per_day(),
            code_attempts: default_code_attempts(),
            pending_ttl_secs: default_pending_ttl(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiConfig {
    /// Browser session lifetime, seconds (default 12h).
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    /// Directory of HTML templates that override the built-in ones by file
    /// name (consent screen, dashboard, …). Built-ins are embedded in the
    /// binary and used for anything not present here. Loaded at startup;
    /// a missing directory is an error, a partial one is fine.
    #[serde(default)]
    pub templates_dir: Option<String>,
}

impl Default for UiConfig {
    fn default() -> Self {
        UiConfig {
            session_ttl_secs: default_session_ttl(),
            templates_dir: None,
        }
    }
}

/// Display fields published in `/.well-known/aauth-person.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataConfig {
    #[serde(default)]
    pub name: Option<String>,
    /// Markdown. Consumers MUST sanitize before rendering.
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub logo_dark_uri: Option<String>,
    #[serde(default)]
    pub documentation_uri: Option<String>,
    #[serde(default)]
    pub tos_uri: Option<String>,
    #[serde(default)]
    pub policy_uri: Option<String>,
}

/// OpenTelemetry (metrics + traces) exported over OTLP/HTTP. Disabled by
/// default. Not yet wired in; accepted in the config now so a file written
/// for that release parses today.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Master switch. Also settable via `PSD_TELEMETRY_ENABLED=1`.
    #[serde(default)]
    pub enabled: bool,
    /// OTLP/HTTP base endpoint, e.g. "http://otel-collector:4318".
    /// Env: `OTEL_EXPORTER_OTLP_ENDPOINT`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// `service.name` in the emitted resource. Default "psd".
    /// Env: `OTEL_SERVICE_NAME`.
    #[serde(default)]
    pub service_name: Option<String>,
    /// Metric export interval in seconds (default 30).
    #[serde(default)]
    pub metric_interval_secs: Option<u64>,
}

fn default_listen() -> String {
    "127.0.0.1:8430".into()
}
fn default_keys_file() -> String {
    "psd-keys.json".into()
}
fn default_backend() -> String {
    "sqlite".into()
}
fn default_db_path() -> String {
    "psd.db".into()
}
fn default_token_ttl() -> u64 {
    3600
}
fn default_signature_window() -> u64 {
    60
}
fn default_resource_token_max_age() -> u64 {
    300
}
fn default_retention_slack() -> u64 {
    3600
}
fn default_pairwise() -> String {
    "pairwise".into()
}
fn default_passkey() -> String {
    "passkey".into()
}
fn default_channels() -> Vec<String> {
    vec!["web".into()]
}
fn default_resources_per_agent_per_day() -> u32 {
    50
}
fn default_code_attempts() -> u32 {
    5
}
fn default_pending_ttl() -> u64 {
    600
}
fn default_session_ttl() -> u64 {
    12 * 3600
}
fn default_max_body() -> usize {
    64 * 1024
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read config {path}: {e}"))?;
        let mut cfg: Config =
            serde_json::from_str(&raw).map_err(|e| format!("invalid config {path}: {e}"))?;
        cfg.apply_env();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Environment overrides. The environment wins over the file.
    pub fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("PSD_ISSUER") {
            self.issuer = v;
        }
        if let Ok(v) = std::env::var("PSD_LISTEN") {
            self.listen = v;
        }
        if let Ok(v) = std::env::var("PSD_KEYS_FILE") {
            self.keys_file = v;
        }
        if let Ok(v) = std::env::var("PSD_DB_PATH") {
            self.storage.path = v;
        }
        if let Ok(v) = std::env::var("PSD_TELEMETRY_ENABLED") {
            self.telemetry.enabled = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Ok(v) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
            self.telemetry.endpoint.get_or_insert(v);
        }
        if let Ok(v) = std::env::var("OTEL_SERVICE_NAME") {
            self.telemetry.service_name.get_or_insert(v);
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        aauth_core::ident::validate_server_identifier(&self.issuer, self.insecure_dev_mode)
            .map_err(|_| {
                format!(
                    "issuer '{}' is not a valid AAuth server identifier \
                     (https://host, lowercase, no port/path/trailing slash). \
                     Set insecure_dev_mode=true for local http development.",
                    self.issuer
                )
            })?;
        if self.person_token_ttl_secs == 0 || self.person_token_ttl_secs > MAX_TOKEN_TTL_SECS {
            return Err(format!(
                "person_token_ttl_secs must be 1..={MAX_TOKEN_TTL_SECS} \
                 (person tokens MUST NOT live longer than one hour)"
            ));
        }
        if self.auth_token_ttl_secs == 0 || self.auth_token_ttl_secs > MAX_TOKEN_TTL_SECS {
            return Err(format!(
                "auth_token_ttl_secs must be 1..={MAX_TOKEN_TTL_SECS} \
                 (auth tokens MUST NOT live longer than one hour)"
            ));
        }
        if self.signature_window_secs == 0 || self.signature_window_secs > 3600 {
            return Err("signature_window_secs must be 1..=3600 (default 60)".into());
        }
        if self.resource_token_max_age_secs == 0 || self.resource_token_max_age_secs > 3600 {
            return Err(
                "resource_token_max_age_secs must be 1..=3600 (resource tokens SHOULD NOT \
                 outlive 5 minutes; default 300)"
                    .into(),
            );
        }
        match self.storage.backend.as_str() {
            "sqlite" => {
                if self.storage.path.is_empty() {
                    return Err("storage.path is required for the sqlite backend".into());
                }
            }
            "postgres" => {
                return Err(
                    "storage.backend 'postgres' is planned but not implemented in this build; \
                     use \"sqlite\""
                        .into(),
                )
            }
            other => {
                return Err(format!(
                    "storage.backend '{other}' is not supported; use \"sqlite\""
                ))
            }
        }
        if self.directed_sub.mode != "pairwise" {
            return Err(format!(
                "directed_sub.mode '{}' is not supported; only \"pairwise\" is implemented",
                self.directed_sub.mode
            ));
        }
        match self.person_auth.method.as_str() {
            "passkey" => {}
            "oidc" => {
                return Err(
                    "person_auth.method 'oidc' is planned for organisation deployments but not \
                     implemented in this build; use \"passkey\""
                        .into(),
                )
            }
            other => {
                return Err(format!(
                    "person_auth.method '{other}' is not supported; use \"passkey\""
                ))
            }
        }
        if self.notify.channels.is_empty() {
            return Err("notify.channels must name at least one channel (\"web\")".into());
        }
        for ch in &self.notify.channels {
            match ch.as_str() {
                "web" => {}
                "webhook" => {
                    match &self.notify.webhook_url {
                        Some(u) if u.starts_with("https://") => {}
                        Some(u) if self.insecure_dev_mode && u.starts_with("http://") => {}
                        _ => return Err(
                            "notify.channels includes \"webhook\" but notify.webhook_url is not \
                             an https:// URL"
                                .into(),
                        ),
                    }
                }
                other => {
                    return Err(format!(
                        "notify.channels entry '{other}' is not supported (\"web\", \"webhook\")"
                    ))
                }
            }
        }
        if self.limits.resources_per_agent_per_day == 0 {
            return Err("limits.resources_per_agent_per_day must be at least 1".into());
        }
        if self.limits.code_attempts == 0 {
            return Err("limits.code_attempts must be at least 1".into());
        }
        if self.limits.pending_ttl_secs < 30 {
            return Err("limits.pending_ttl_secs must be at least 30".into());
        }
        if self.ui.session_ttl_secs < 60 {
            return Err("ui.session_ttl_secs must be at least 60".into());
        }
        if let Some(dir) = &self.ui.templates_dir {
            if !std::path::Path::new(dir).is_dir() {
                return Err(format!(
                    "ui.templates_dir '{dir}' is not a directory (built-in templates are used \
                     when this is unset)"
                ));
            }
        }
        if self.max_body_bytes < 1024 {
            return Err("max_body_bytes must be at least 1024".into());
        }
        if let Some(a) = &self.expected_authority {
            let host = a.split(':').next().unwrap_or("");
            let port_ok = match a.split_once(':') {
                Some((_, p)) => !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()),
                None => true,
            };
            if host.is_empty()
                || !port_ok
                || a.contains(['/', '?', '#', '@'])
                || a.chars().any(|c| c.is_ascii_uppercase())
            {
                return Err(
                    "expected_authority must be a lowercase host, optionally :port, with no \
                     scheme or path (e.g. \"ps.example\" or \"ps.internal:8430\")"
                        .into(),
                );
            }
        }
        for (name, value) in [
            ("logo_uri", &self.metadata.logo_uri),
            ("logo_dark_uri", &self.metadata.logo_dark_uri),
            ("documentation_uri", &self.metadata.documentation_uri),
            ("tos_uri", &self.metadata.tos_uri),
            ("policy_uri", &self.metadata.policy_uri),
        ] {
            if let Some(v) = value {
                if !v.starts_with("https://") {
                    return Err(format!(
                        "metadata.{name} must be an https:// URL (AAuth §Metadata Documents)"
                    ));
                }
            }
        }
        if let Some(ep) = &self.telemetry.endpoint {
            if !(ep.starts_with("http://") || ep.starts_with("https://")) {
                return Err("telemetry.endpoint must start with http:// or https://".into());
            }
        }
        Ok(())
    }

    /// The `@authority` an inbound signed request must carry: the issuer's
    /// host (with the port only when the dev-mode issuer names one), unless
    /// `expected_authority` overrides it.
    pub fn issuer_authority(&self) -> String {
        if let Some(a) = &self.expected_authority {
            return a.to_ascii_lowercase();
        }
        self.issuer
            .strip_prefix("https://")
            .or_else(|| self.issuer.strip_prefix("http://"))
            .unwrap_or(&self.issuer)
            .to_string()
    }

    /// The person-token retention horizon past `exp`. It has a floor and a
    /// ceiling: forget a record early and a resource token naming it is
    /// wrongly rejected; never forget and the table grows without bound.
    pub fn retention_secs(&self) -> u64 {
        self.resource_token_max_age_secs + self.retention_slack_secs
    }
}

pub const EXAMPLE_CONFIG: &str = r#"{
  "issuer": "https://ps.example.com",
  "listen": "127.0.0.1:8430",
  "keys_file": "/var/lib/psd/psd-keys.json",
  "storage": { "backend": "sqlite", "path": "/var/lib/psd/psd.db" },

  "person_token_ttl_secs": 3600,
  "auth_token_ttl_secs": 3600,
  "signature_window_secs": 60,
  "resource_token_max_age_secs": 300,
  "retention_slack_secs": 3600,

  "directed_sub": { "mode": "pairwise" },
  "person_auth": { "method": "passkey" },
  "notify": { "channels": ["web"], "webhook_url": null },
  "limits": { "resources_per_agent_per_day": 50, "code_attempts": 5, "pending_ttl_secs": 600 },
  "ui": { "session_ttl_secs": 43200, "templates_dir": null },

  "missions": { "enabled": false },
  "federation": { "enabled": false },

  "metadata": {
    "name": "Example Person Server",
    "description": "Manage which agents act for you and review what they do.",
    "documentation_uri": "https://personserver.dev/docs/"
  },
  "telemetry": { "enabled": false, "endpoint": "http://localhost:4318" },
  "insecure_dev_mode": false
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(v: serde_json::Value) -> Result<Config, String> {
        let cfg: Config = serde_json::from_value(v).map_err(|e| e.to_string())?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn example_config_is_valid() {
        let cfg: Config = serde_json::from_str(EXAMPLE_CONFIG).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.issuer_authority(), "ps.example.com");
        assert_eq!(cfg.retention_secs(), 3900);
    }

    #[test]
    fn minimal_config_defaults() {
        let cfg = parse(serde_json::json!({ "issuer": "https://ps.example" })).unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:8430");
        assert_eq!(cfg.storage.backend, "sqlite");
        assert_eq!(cfg.person_token_ttl_secs, 3600);
        assert_eq!(cfg.directed_sub.mode, "pairwise");
        assert_eq!(cfg.person_auth.method, "passkey");
        assert_eq!(cfg.notify.channels, vec!["web".to_string()]);
    }

    #[test]
    fn issuer_rules() {
        assert!(parse(serde_json::json!({ "issuer": "http://ps.example" })).is_err());
        assert!(parse(serde_json::json!({ "issuer": "https://ps.example/" })).is_err());
        assert!(parse(serde_json::json!({ "issuer": "https://PS.example" })).is_err());
        assert!(parse(serde_json::json!({ "issuer": "https://ps.example:8443" })).is_err());
        // dev mode relaxes scheme and port, and the authority keeps the port
        let cfg = parse(serde_json::json!({
            "issuer": "http://127.0.0.1:8430", "insecure_dev_mode": true
        }))
        .unwrap();
        assert_eq!(cfg.issuer_authority(), "127.0.0.1:8430");
    }

    #[test]
    fn expected_authority_override() {
        let cfg = parse(serde_json::json!({
            "issuer": "https://ps.example", "expected_authority": "ps.internal:8430"
        }))
        .unwrap();
        assert_eq!(cfg.issuer_authority(), "ps.internal:8430");
        for bad in [
            "https://ps.example",
            "ps.example/x",
            "PS.example",
            "ps.example:x",
            "",
        ] {
            assert!(
                parse(
                    serde_json::json!({ "issuer": "https://ps.example", "expected_authority": bad })
                )
                .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn token_ttl_caps() {
        assert!(parse(serde_json::json!({
            "issuer": "https://ps.example", "person_token_ttl_secs": 3601
        }))
        .is_err());
        assert!(parse(serde_json::json!({
            "issuer": "https://ps.example", "auth_token_ttl_secs": 0
        }))
        .is_err());
    }

    #[test]
    fn unimplemented_features_fail_fast() {
        for (k, v) in [
            (
                "storage",
                serde_json::json!({ "backend": "postgres", "path": "x" }),
            ),
            ("person_auth", serde_json::json!({ "method": "oidc" })),
            ("directed_sub", serde_json::json!({ "mode": "public" })),
        ] {
            let mut doc = serde_json::json!({ "issuer": "https://ps.example" });
            doc[k] = v;
            let err = parse(doc).unwrap_err();
            assert!(
                err.contains(k) || err.contains("not implemented"),
                "{k}: {err}"
            );
        }
    }

    #[test]
    fn unknown_field_is_rejected() {
        let err = parse(serde_json::json!({
            "issuer": "https://ps.example", "isuer": "typo"
        }))
        .unwrap_err();
        assert!(err.contains("unknown field"), "{err}");
    }

    #[test]
    fn metadata_uris_must_be_https() {
        let err = parse(serde_json::json!({
            "issuer": "https://ps.example",
            "metadata": { "logo_uri": "http://ps.example/logo.png" }
        }))
        .unwrap_err();
        assert!(err.contains("metadata.logo_uri"), "{err}");
    }

    #[test]
    fn webhook_channel_needs_https_url() {
        let err = parse(serde_json::json!({
            "issuer": "https://ps.example",
            "notify": { "channels": ["web", "webhook"] }
        }))
        .unwrap_err();
        assert!(err.contains("webhook_url"), "{err}");
        parse(serde_json::json!({
            "issuer": "https://ps.example",
            "notify": { "channels": ["webhook"], "webhook_url": "https://hooks.example/psd" }
        }))
        .unwrap();
    }
}
