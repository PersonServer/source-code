//! OpenID Connect person login: psd as a Relying Party (Authorization Code +
//! PKCE) to the organisation's identity provider.
//!
//! What lives here is everything that talks to or reasons about the IdP —
//! discovery, the authorization URL, the code exchange, ID-token verification
//! against the IdP's keys, and the `required_claims` gate. The browser flow
//! (rows, cookies, sessions) is in `handlers/ui.rs`; nothing here knows about
//! consent, agents or tokens psd issues. An IdP session authenticates a
//! *human in a browser* and does nothing else.
//!
//! Every fetch goes through the same egress admission as agent-token
//! discovery: the issuer is operator-supplied, but the JWKS host is the
//! IdP's word, so it must be same-origin unless the operator listed it.

use std::fmt;
use std::time::{Duration, Instant};

use aauth_core::jwt;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::anyjwk::{AnyJwk, SUPPORTED_ALGS};
use crate::config::{Config, OidcConfig};
use crate::httpc::{self, EgressPolicy};

/// Same floor and cap as agent-token discovery: never fetch the IdP's keys
/// more than once a minute, never trust a key set older than a day.
const FETCH_FLOOR: Duration = Duration::from_secs(60);
const MAX_AGE: Duration = Duration::from_secs(24 * 3600);
/// A sign-in attempt that has not come back in this long is abandoned.
pub const LOGIN_TTL_SECS: u64 = 600;

struct KeyCache {
    keys: Vec<AnyJwk>,
    fetched_at: Instant,
    last_attempt: Instant,
}

/// The IdP as discovered at startup, plus the client credentials and the key
/// cache. Built once; `Debug` never shows the secret.
pub struct OidcRuntime {
    pub cfg: OidcConfig,
    client_secret: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    /// `{psd issuer}/login/oidc/callback` — what the operator registers.
    pub redirect_uri: String,
    egress: EgressPolicy,
    keys: Mutex<KeyCache>,
}

impl fmt::Debug for OidcRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcRuntime")
            .field("issuer", &self.cfg.issuer)
            .field("client_id", &self.cfg.client_id)
            .field("client_secret", &"<redacted>")
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("jwks_uri", &self.jwks_uri)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// Why a sign-in could not be completed. `Unavailable` is the IdP (or our
/// egress) failing, never a verdict about the person; the others are.
#[derive(Debug)]
pub enum LoginError {
    /// The IdP could not be reached or answered outside its contract.
    Unavailable(String),
    /// The ID token did not verify or did not say what it must.
    InvalidToken(String),
    /// The person authenticated but `required_claims` were not met.
    NotPermitted(String),
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::Unavailable(d)
            | LoginError::InvalidToken(d)
            | LoginError::NotPermitted(d) => {
                write!(f, "{d}")
            }
        }
    }
}

/// What psd takes from a verified ID token.
#[derive(Debug, Clone)]
pub struct Verified {
    pub iss: String,
    pub sub: String,
    pub email: Option<String>,
    pub tenant: Option<String>,
    pub display_name: String,
}

impl OidcRuntime {
    /// Read the client secret and run discovery. Called once at startup so
    /// a typo in the issuer, an unreachable IdP or a wrong secret path fails
    /// there, not on the first person's login.
    pub async fn discover(cfg: &Config, egress: &EgressPolicy) -> Result<OidcRuntime, String> {
        let o = cfg
            .person_auth
            .oidc
            .clone()
            .ok_or("person_auth.oidc is not configured")?;
        let client_secret = std::fs::read_to_string(&o.client_secret_file)
            .map_err(|e| format!("cannot read person_auth.oidc.client_secret_file: {e}"))?
            .trim()
            .to_string();
        if client_secret.is_empty() {
            return Err("person_auth.oidc.client_secret_file is empty".into());
        }
        let url = format!("{}/.well-known/openid-configuration", o.issuer);
        let doc = httpc::get_json(&url, egress)
            .await
            .map_err(|e| format!("OIDC discovery failed ({url}): {e}"))?;
        // OpenID Connect Discovery §4.3: the document's issuer MUST equal the
        // one it was fetched for, byte-for-byte — the host-poisoning check.
        match doc.get("issuer").and_then(|v| v.as_str()) {
            Some(i) if i == o.issuer => {}
            Some(i) => {
                return Err(format!(
                    "OIDC discovery: document at {url} declares issuer {i:?}, configured \
                     {:?} — they must be identical",
                    o.issuer
                ))
            }
            None => return Err(format!("OIDC discovery: document at {url} has no issuer")),
        }
        let endpoint = |name: &str| -> Result<String, String> {
            let v = doc
                .get(name)
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("OIDC discovery: document has no {name}"))?;
            let ok =
                v.starts_with("https://") || (cfg.insecure_dev_mode && v.starts_with("http://"));
            if !ok {
                return Err(format!("OIDC discovery: {name} is not https"));
            }
            Ok(v.to_string())
        };
        let authorization_endpoint = endpoint("authorization_endpoint")?;
        let token_endpoint = endpoint("token_endpoint")?;
        let jwks_uri = endpoint("jwks_uri")?;
        // The JWKS host is the IdP's word, not the operator's: same origin as
        // the issuer unless explicitly admitted (Google Workspace publishes
        // its keys on www.googleapis.com; the operator lists it).
        let iss_host = aauth_core::ident::host_of(&o.issuer);
        let jwks_host = aauth_core::ident::host_of(&jwks_uri);
        match (&iss_host, &jwks_host) {
            (Some(a), Some(b)) if a == b => {}
            (_, Some(b)) if cfg.jwks_cross_origin_hosts.iter().any(|h| h == b) => {}
            _ => {
                return Err(format!(
                    "OIDC discovery: jwks_uri {jwks_uri} is on a different host than the \
                     issuer; add that host to jwks_cross_origin_hosts to allow it"
                ))
            }
        }
        if let Some(algs) = doc
            .get("id_token_signing_alg_values_supported")
            .and_then(|v| v.as_array())
        {
            let usable = algs
                .iter()
                .filter_map(|a| a.as_str())
                .any(|a| SUPPORTED_ALGS.contains(&a));
            if !usable {
                return Err(format!(
                    "OIDC discovery: the provider signs ID tokens with none of {SUPPORTED_ALGS:?}"
                ));
            }
        }
        let rt = OidcRuntime {
            redirect_uri: format!("{}/login/oidc/callback", cfg.issuer),
            cfg: o,
            client_secret,
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
            egress: egress.clone(),
            keys: Mutex::new(KeyCache {
                keys: Vec::new(),
                fetched_at: Instant::now() - MAX_AGE,
                last_attempt: Instant::now() - FETCH_FLOOR,
            }),
        };
        // Keys now too, so a JWKS problem is also a startup error.
        rt.refresh_keys().await.map_err(|e| e.to_string())?;
        Ok(rt)
    }

    /// The URL to send the browser to. `state`, `nonce` and the PKCE
    /// challenge are the caller's; they are bound to the sign-in row there.
    pub fn authorization_url(&self, state: &str, nonce: &str, code_challenge: &str) -> String {
        let scope = self.cfg.scopes.join(" ");
        let sep = if self.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        format!(
            "{}{sep}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}\
             &code_challenge={}&code_challenge_method=S256",
            self.authorization_endpoint,
            form_encode(&self.cfg.client_id),
            form_encode(&self.redirect_uri),
            form_encode(&scope),
            form_encode(state),
            form_encode(nonce),
            form_encode(code_challenge),
        )
    }

    /// Exchange the authorization code for the ID token (RFC 6749 §4.1.3
    /// with PKCE, `client_secret_basic`).
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<String, LoginError> {
        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
            form_encode(code),
            form_encode(&self.redirect_uri),
            form_encode(&self.cfg.client_id),
            form_encode(code_verifier),
        );
        let basic = aauth_core::b64::encode_std(
            format!(
                "{}:{}",
                form_encode(&self.cfg.client_id),
                form_encode(&self.client_secret)
            )
            .as_bytes(),
        );
        let headers = vec![
            (
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("authorization".to_string(), format!("Basic {basic}")),
        ];
        let resp = httpc::request(
            "POST",
            &self.token_endpoint,
            &headers,
            Some(body.as_bytes()),
            &self.egress,
        )
        .await
        .map_err(|e| LoginError::Unavailable(format!("token endpoint: {e}")))?;
        let json = resp.json();
        if resp.status != 200 {
            let err = json
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("no error code");
            // invalid_grant is the code being wrong/spent/expired — the
            // person's attempt failed, not the IdP. Anything else is the
            // IdP or our client registration.
            return Err(if err == "invalid_grant" {
                LoginError::InvalidToken(format!("the provider refused the code ({err})"))
            } else {
                LoginError::Unavailable(format!("token endpoint answered {} ({err})", resp.status))
            });
        }
        json.get("id_token")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| LoginError::InvalidToken("token response carries no id_token".into()))
    }

    /// Verify an ID token (OpenID Connect Core §3.1.3.7): signature by one
    /// of the IdP's keys (refreshed once on an unknown `kid`), `iss`, `aud`
    /// (+ `azp` when plural), `exp`, `iat`, and the caller's `nonce`. Then
    /// the `required_claims` gate. Returns what psd needs from the claims.
    pub async fn verify_id_token(
        &self,
        id_token: &str,
        nonce_hash: &str,
    ) -> Result<Verified, LoginError> {
        let bad = |d: String| LoginError::InvalidToken(d);
        let decoded = jwt::decode(id_token).map_err(|_| bad("id_token is not a JWT".into()))?;
        let alg = decoded.header.alg.clone();
        if !SUPPORTED_ALGS.contains(&alg.as_str()) {
            return Err(bad(format!("id_token alg {alg:?} is not accepted")));
        }
        let kid = decoded.header.kid.clone();
        let key = self.key_for(kid.as_deref(), &alg).await?;
        key.verify(&alg, decoded.signing_input.as_bytes(), &decoded.signature)
            .map_err(|_| bad("id_token signature does not verify".into()))?;
        let p = &decoded.payload;
        let s = |n: &str| p.get(n).and_then(|v| v.as_str()).map(String::from);
        let iss = s("iss").ok_or_else(|| bad("id_token has no iss".into()))?;
        if iss != self.cfg.issuer {
            return Err(bad("id_token iss is not the configured provider".into()));
        }
        // aud may be a string or an array; when it is plural, azp names us.
        let aud_ok = match p.get("aud") {
            Some(serde_json::Value::String(a)) => a == &self.cfg.client_id,
            Some(serde_json::Value::Array(list)) => {
                list.iter()
                    .any(|a| a.as_str() == Some(self.cfg.client_id.as_str()))
                    && (list.len() == 1
                        || p.get("azp").and_then(|v| v.as_str())
                            == Some(self.cfg.client_id.as_str()))
            }
            _ => false,
        };
        if !aud_ok {
            return Err(bad("id_token aud does not name this client".into()));
        }
        let now = aauth_core::now_unix() as i64;
        match p.get("exp").and_then(|v| v.as_i64()) {
            Some(exp) if exp > now => {}
            Some(_) => return Err(bad("id_token expired".into())),
            None => return Err(bad("id_token has no exp".into())),
        }
        if p.get("iat").and_then(|v| v.as_i64()).unwrap_or(0) > now + 60 {
            return Err(bad("id_token iat is in the future".into()));
        }
        // The nonce binds this token to the sign-in attempt that asked for
        // it; a token from any other attempt (or a replayed one) fails here.
        match s("nonce") {
            Some(n) if crate::ui::ct_eq(&sha256_hex(&n), nonce_hash) => {}
            Some(_) => return Err(bad("id_token nonce does not match this sign-in".into())),
            None => return Err(bad("id_token has no nonce".into())),
        }
        let sub = s("sub").ok_or_else(|| bad("id_token has no sub".into()))?;
        // The gate.
        for (path, matcher) in &self.cfg.required_claims {
            let actual = lookup_claim(p, path).ok_or_else(|| {
                LoginError::NotPermitted(format!("required claim {path:?} is absent"))
            })?;
            if !claim_matches(matcher, actual) {
                return Err(LoginError::NotPermitted(format!(
                    "required claim {path:?} does not satisfy the policy"
                )));
            }
        }
        let email = s("email");
        let tenant = self
            .cfg
            .tenant_claim
            .as_deref()
            .and_then(|c| lookup_claim(p, c))
            .and_then(claim_text);
        let display_name = self
            .cfg
            .display_name_claims
            .iter()
            .filter_map(|c| lookup_claim(p, c).and_then(claim_text))
            .find(|v| !v.trim().is_empty())
            .unwrap_or_else(|| sub.clone());
        Ok(Verified {
            iss,
            sub,
            email,
            tenant,
            display_name,
        })
    }

    /// The key for `kid` (any usable key when the token names none), from
    /// the cache or a refresh under the floor.
    async fn key_for(&self, kid: Option<&str>, alg: &str) -> Result<AnyJwk, LoginError> {
        let pick = |keys: &[AnyJwk]| -> Option<AnyJwk> {
            keys.iter()
                .find(|k| match kid {
                    Some(id) => k.kid.as_deref() == Some(id) && k.supports_alg(alg),
                    None => k.supports_alg(alg),
                })
                .cloned()
        };
        {
            let cache = self.keys.lock().await;
            if cache.fetched_at.elapsed() < MAX_AGE {
                if let Some(k) = pick(&cache.keys) {
                    return Ok(k);
                }
            }
        }
        // Unknown kid (rotation) or stale cache: refresh once, floor allowing.
        match self.refresh_keys().await {
            Ok(()) => {}
            Err(LoginError::Unavailable(d)) => {
                let cache = self.keys.lock().await;
                // A recent successful fetch is authoritative for the minute.
                if cache.fetched_at.elapsed() < FETCH_FLOOR {
                    return Err(LoginError::InvalidToken(
                        "id_token is signed with a key the provider does not publish".into(),
                    ));
                }
                return Err(LoginError::Unavailable(d));
            }
            Err(e) => return Err(e),
        }
        let cache = self.keys.lock().await;
        pick(&cache.keys).ok_or_else(|| {
            LoginError::InvalidToken(
                "id_token is signed with a key the provider does not publish".into(),
            )
        })
    }

    async fn refresh_keys(&self) -> Result<(), LoginError> {
        {
            let mut cache = self.keys.lock().await;
            let since = cache.last_attempt.elapsed();
            if since < FETCH_FLOOR && cache.fetched_at != cache.last_attempt {
                // The last attempt within the floor failed; do not hammer.
                return Err(LoginError::Unavailable(format!(
                    "the provider's keys could not be fetched a moment ago; retry in {} s",
                    (FETCH_FLOOR - since).as_secs().max(1)
                )));
            }
            if since < FETCH_FLOOR && !cache.keys.is_empty() {
                // Fetched successfully within the floor: nothing newer exists.
                return Ok(());
            }
            cache.last_attempt = Instant::now();
        }
        let doc = httpc::get_json(&self.jwks_uri, &self.egress)
            .await
            .map_err(|e| LoginError::Unavailable(format!("provider JWKS: {e}")))?;
        let keys = AnyJwk::parse_jwks(&doc);
        if keys.is_empty() {
            return Err(LoginError::Unavailable(
                "provider JWKS carries no usable key".into(),
            ));
        }
        let mut cache = self.keys.lock().await;
        cache.keys = keys;
        cache.fetched_at = cache.last_attempt;
        Ok(())
    }
}

/// A fresh PKCE pair (RFC 7636 §4): a 43-character verifier and its S256
/// challenge.
pub fn pkce_pair() -> (String, String) {
    let verifier = aauth_core::rand_token(256);
    let challenge = aauth_core::b64::encode(&Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

pub fn sha256_hex(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in d {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `application/x-www-form-urlencoded` percent-encoding of one value.
pub fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Resolve a dotted claim path (`realm_access.roles`), preferring the
/// longest top-level key so a claim literally named `a.b` still resolves.
/// Adapted from apd (MIT OR Apache-2.0).
pub fn lookup_claim<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let obj = value.as_object()?;
    if let Some(v) = obj.get(path) {
        return Some(v);
    }
    let mut idx = path.len();
    while let Some(dot) = path[..idx].rfind('.') {
        let (head, tail) = (&path[..dot], &path[dot + 1..]);
        if let Some(inner) = obj.get(head) {
            if let Some(v) = lookup_claim(inner, tail) {
                return Some(v);
            }
            if let Some(v) = inner.get(tail) {
                return Some(v);
            }
        }
        idx = dot;
    }
    None
}

/// Match a claim value against a matcher: exact string, trailing-`*` prefix,
/// or an array of those (any-of). An array-valued *actual* claim — `groups`,
/// `roles` — matches when any element does, and an empty array never does
/// (a claim present but empty must not satisfy a requirement).
/// Adapted from apd (MIT OR Apache-2.0), with the array-valued case added.
pub fn claim_matches(matcher: &serde_json::Value, actual: &serde_json::Value) -> bool {
    let actual_str = match actual {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Array(values) => {
            return values.iter().any(|v| claim_matches(matcher, v));
        }
        _ => return false,
    };
    let one = |pattern: &str| match pattern.strip_suffix('*') {
        Some(prefix) => actual_str.starts_with(prefix),
        None => actual_str == pattern,
    };
    match matcher {
        serde_json::Value::String(pattern) => one(pattern),
        serde_json::Value::Array(allowed) => allowed.iter().filter_map(|v| v.as_str()).any(one),
        _ => false,
    }
}

fn claim_text(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_semantics() {
        let j = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        assert!(claim_matches(&j(r#""admins""#), &j(r#""admins""#)));
        assert!(!claim_matches(&j(r#""admins""#), &j(r#""users""#)));
        assert!(claim_matches(&j(r#""acme-*""#), &j(r#""acme-eng""#)));
        assert!(claim_matches(&j(r#"["a","b"]"#), &j(r#""b""#)));
        // Array-valued actual claims: any element; empty never.
        assert!(claim_matches(
            &j(r#""admins""#),
            &j(r#"["users","admins"]"#)
        ));
        assert!(!claim_matches(&j(r#""admins""#), &j(r#"[]"#)));
        assert!(!claim_matches(&j(r#""admins""#), &j(r#"["users"]"#)));
        assert!(claim_matches(&j(r#""true""#), &j("true")));
        assert!(!claim_matches(&j("42"), &j(r#""42""#)));
        let claims = j(r#"{"realm_access":{"roles":["psd-users"]},"a.b":"lit","hd":"acme.com"}"#);
        assert!(claim_matches(
            &j(r#""psd-users""#),
            lookup_claim(&claims, "realm_access.roles").unwrap()
        ));
        assert_eq!(lookup_claim(&claims, "a.b").unwrap(), "lit");
        assert!(lookup_claim(&claims, "missing").is_none());
    }

    #[test]
    fn pkce_and_encoding() {
        let (v, c) = pkce_pair();
        assert!(v.len() >= 43 && v.len() <= 128);
        assert_eq!(c, aauth_core::b64::encode(&Sha256::digest(v.as_bytes())));
        assert_eq!(form_encode("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
        assert_eq!(form_encode("safe-._~09Az"), "safe-._~09Az");
    }
}
