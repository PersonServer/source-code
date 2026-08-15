//! Per-request context and inbound verification.
//!
//! [`ReqCtx`] buffers the body and exposes the pieces RFC 9421 verification
//! needs. [`verify_agent_request`] is the one path every agent-facing PS
//! endpoint goes through (AAuth §Verification, §Agent Token Verification,
//! §Covered Components):
//!
//! 1. the request is addressed to us (`@authority` = issuer host)
//! 2. `Signature-Input` / `Signature` / `Signature-Key` parse and cover
//!    `@method`, `@authority`, `@path`, `signature-key` — plus
//!    `content-type` and `content-digest` on endpoints that take a body —
//!    with `created` inside the window
//! 3. the scheme is `jwt` (the only one AAuth agents use)
//! 4. the JWT is an agent token: `typ`, `dwk`, a valid `iss`, discovered
//!    JWKS by `kid`, signature, `exp`/`iat`
//! 5. `cnf.jwk` signed the HTTP request
//! 6. `Content-Digest` actually matches the body we received
//! 7. sub-agents (`parent_agent`) may not call the PS directly
//! 8. the signature has not been seen before inside the window
//!
//! Every signature failure is a `401` + `Signature-Error`; the request-level
//! and policy failures (1, 7) are `400 invalid_request`. Nothing here decides
//! *authorization* — that is the handler's job, and it produces the `403`s.
//!
//! Every Agent Provider is foreign to a Person Server, so the `jwt` scheme
//! always resolves the token's key through JWKS discovery — there is no
//! "our own tokens" shortcut here.
//!
//! `ReqCtx` is adapted from apd (MIT OR Apache-2.0).

use std::sync::Arc;

use aauth_core::jwk::Jwk;
use aauth_core::jwt::{self, ClaimExt};
use aauth_core::sig::{self, RequestParts, SigError, SigErrorCode, VerifyPolicy};
use aauth_core::sigkey::SigKeyScheme;
use aauth_core::tokens;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, StatusCode};
use sha2::{Digest, Sha256, Sha512};

use crate::app::App;
use crate::problem::ApiError;

pub struct ReqCtx {
    pub method: String,
    pub authority: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ReqCtx {
    /// Read a request, enforcing the body size limit.
    pub async fn read(req: Request<Incoming>, max_body: usize) -> Result<ReqCtx, ApiError> {
        let (parts, body) = req.into_parts();
        let method = parts.method.as_str().to_string();
        let path = parts.uri.path().to_string();
        let query = parts
            .uri
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();

        // @authority: prefer Host header, lowercased, with a scheme-default
        // port stripped so it matches an RFC 9421-conformant signer that
        // normalizes it away (RFC 9421 §2.2.3).
        let authority = parts
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase())
            .or_else(|| {
                parts
                    .uri
                    .authority()
                    .map(|a| a.as_str().to_ascii_lowercase())
            })
            .map(|a| {
                a.strip_suffix(":443")
                    .or_else(|| a.strip_suffix(":80"))
                    .map(|h| h.to_string())
                    .unwrap_or(a)
            })
            .unwrap_or_default();

        let mut headers = Vec::new();
        for (name, value) in parts.headers.iter() {
            if let Ok(v) = value.to_str() {
                headers.push((name.as_str().to_ascii_lowercase(), v.to_string()));
            }
        }

        let collected = http_body_util::Limited::new(body, max_body)
            .collect()
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "invalid_request",
                    "request body too large or unreadable",
                )
            })?;

        Ok(ReqCtx {
            method,
            authority,
            path,
            query,
            headers,
            body: collected.to_bytes().to_vec(),
        })
    }

    /// Canonical header lookup per RFC 9421 (comma-join repeats, trim OWS).
    pub fn header(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.trim())
            .collect();
        if values.is_empty() {
            None
        } else {
            Some(values.join(", "))
        }
    }

    pub fn parse_json(&self) -> Result<serde_json::Value, ApiError> {
        if self.body.is_empty() {
            return Ok(serde_json::json!({}));
        }
        serde_json::from_slice(&self.body).map_err(|e| {
            ApiError::bad_request("invalid_request", format!("invalid JSON body: {e}"))
        })
    }

    fn request_parts<'a>(&'a self, lookup: &'a dyn Fn(&str) -> Option<String>) -> RequestParts<'a> {
        RequestParts {
            method: &self.method,
            authority: &self.authority,
            path: &self.path,
            query: &self.query,
            header: lookup,
        }
    }
}

/// The successfully-verified signer of an agent-facing request.
pub struct AgentSigner {
    pub claims: tokens::AgentTokenClaims,
    /// The compact agent token as presented (forwarded to an Access Server
    /// when federating).
    pub token: String,
    /// The key that signed the HTTP request — the agent token's `cnf.jwk`.
    pub signing_jwk: Jwk,
    /// RFC 7638 thumbprint of `signing_jwk` (compared against a resource
    /// token's `agent_jkt`, and the replay-cache key).
    pub jkt: String,
}

impl AgentSigner {
    /// The agent's identity tuple. `sub` alone is unique only within its
    /// Agent Provider; every lookup keys on `(iss, sub)`.
    pub fn agent(&self) -> (&str, &str) {
        (&self.claims.iss, &self.claims.sub)
    }
}

fn sig_err(code: SigErrorCode, detail: impl Into<String>) -> ApiError {
    ApiError::from_sig_error(SigError::new(code, detail))
}

/// Verify an agent-signed request end to end (see module docs). `body` is
/// true for endpoints that take a JSON body, which additionally requires
/// `content-type` and `content-digest` to be covered and the digest to match.
pub async fn verify_agent_request(
    ctx: &ReqCtx,
    app: &Arc<App>,
    body: bool,
) -> Result<AgentSigner, ApiError> {
    // 1. Addressed to us. A misrouting proxy or a captured request for another
    //    host must not get as far as a network fetch on our behalf.
    let expected_authority = app.cfg.issuer_authority();
    if ctx.authority != expected_authority {
        return Err(ApiError::bad_request(
            "invalid_request",
            format!(
                "request authority '{}' does not match this server ('{}'); the agent must \
                 sign @authority = the PS issuer host",
                ctx.authority, expected_authority
            ),
        ));
    }

    // 2. Structural signature checks + covered components + window. Scoped so
    //    the borrowed header lookup (not `Sync`) is gone before any await.
    let now = aauth_core::now_unix();
    let parsed = {
        let lookup = |name: &str| ctx.header(name);
        let parts = ctx.request_parts(&lookup);
        let extra_required: Vec<String> = if body {
            vec!["content-type".into(), "content-digest".into()]
        } else {
            Vec::new()
        };
        let policy = VerifyPolicy {
            now,
            window_secs: app.cfg.signature_window_secs,
            extra_required,
        };
        sig::parse_request_signature(&parts, &policy).map_err(ApiError::from_sig_error)?
    };

    // 3. AAuth agents MUST use scheme=jwt on PS endpoints.
    let token = match &parsed.scheme {
        SigKeyScheme::Jwt(token) => token.clone(),
        SigKeyScheme::Hwk(_) => {
            return Err(sig_err(
                SigErrorCode::UnsupportedScheme,
                "scheme=hwk is not accepted; present an agent token with scheme=jwt",
            ))
        }
        SigKeyScheme::JktJwt(_) => {
            return Err(sig_err(
                SigErrorCode::UnsupportedScheme,
                "scheme=jkt-jwt is not accepted; present an agent token with scheme=jwt",
            ))
        }
        SigKeyScheme::JwksUri { .. } => {
            return Err(sig_err(
                SigErrorCode::UnsupportedScheme,
                "scheme=jwks_uri is not accepted on this endpoint; present an agent token \
                 with scheme=jwt",
            ))
        }
        SigKeyScheme::Other(s) => {
            return Err(sig_err(
                SigErrorCode::UnsupportedScheme,
                format!("Signature-Key scheme '{s}' is not supported"),
            ))
        }
    };

    // 4. The JWT is an agent token from a discoverable Agent Provider.
    let claims = verify_foreign_agent_token(app, &token, now).await?;

    // 5. The agent token's key signed this request.
    let signing_jwk = claims.cnf.jwk.clone();
    sig::verify_parsed(&parsed, &signing_jwk).map_err(ApiError::from_sig_error)?;
    let jkt = signing_jwk
        .thumbprint()
        .map_err(|_| sig_err(SigErrorCode::InvalidKey, "cnf.jwk has no thumbprint"))?;

    // 6. Body integrity: the covered Content-Digest must be the digest of the
    //    bytes we actually received, or the body was not protected at all.
    if body {
        verify_content_digest(ctx)?;
    }

    // 6b. Revoked by its Agent Provider? (§Token Revocation: the PS MUST deny
    //     subsequent requests presenting that agent token.) Remember every
    //     token that signs here so a later revocation can find the agent.
    if app.store.is_agent_token_revoked(&claims.iss, &claims.jti)? {
        return Err(sig_err(
            SigErrorCode::InvalidJwt,
            "agent token was revoked by its Agent Provider",
        ));
    }
    app.store
        .note_agent_token_seen(&claims.iss, &claims.jti, &claims.sub, claims.exp)?;

    // 7. Single-level depth: a sub-agent MUST NOT call the PS; its parent does.
    if claims.parent_agent.is_some() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "the signing agent token carries parent_agent: a sub-agent must not request \
             from the PS directly; its parent obtains tokens on its behalf using \
             subagent_token",
        ));
    }

    // 8. Replay inside the window (§Freshness and Replay), on state-changing
    //    (body-carrying) requests. Ed25519 is deterministic and `created` is
    //    whole seconds, so a legitimate second GET poll within one second is
    //    byte-identical to a replay — the draft scopes the guard to
    //    state-changing requests for exactly that reason.
    if body
        && !app
            .replay
            .check_and_insert(&jkt, &parsed.signature, app.cfg.signature_window_secs)
    {
        return Err(sig_err(
            SigErrorCode::InvalidSignature,
            "signature replayed: this exact signature was already accepted inside the window",
        ));
    }

    Ok(AgentSigner {
        claims,
        token,
        signing_jwk,
        jkt,
    })
}

/// The verified signer of a server-to-server request (`scheme=jwks_uri`): an
/// AAuth server identified by `id`, whose key `kid` was discovered from
/// `{id}/.well-known/{dwk}`. Used by `/revoke`, where an Agent Provider signs
/// as itself.
#[allow(dead_code)] // `dwk`/`kid` are audit detail for later milestones
pub struct ServerSigner {
    pub id: String,
    pub dwk: String,
    pub kid: String,
}

/// Verify a request signed by a server as itself with the `jwks_uri` scheme.
/// Same structural, authority, digest and replay rules as agent requests.
pub async fn verify_server_request(
    ctx: &ReqCtx,
    app: &Arc<App>,
    body: bool,
) -> Result<ServerSigner, ApiError> {
    let expected_authority = app.cfg.issuer_authority();
    if ctx.authority != expected_authority {
        return Err(ApiError::bad_request(
            "invalid_request",
            format!(
                "request authority '{}' does not match this server ('{}')",
                ctx.authority, expected_authority
            ),
        ));
    }
    let now = aauth_core::now_unix();
    let parsed = {
        let lookup = |name: &str| ctx.header(name);
        let parts = ctx.request_parts(&lookup);
        let extra_required: Vec<String> = if body {
            vec!["content-type".into(), "content-digest".into()]
        } else {
            Vec::new()
        };
        let policy = VerifyPolicy {
            now,
            window_secs: app.cfg.signature_window_secs,
            extra_required,
        };
        sig::parse_request_signature(&parts, &policy).map_err(ApiError::from_sig_error)?
    };
    let (id, dwk, kid) = match &parsed.scheme {
        SigKeyScheme::JwksUri { id, dwk, kid } => (id.clone(), dwk.clone(), kid.clone()),
        _ => {
            let mut e = SigError::new(
                SigErrorCode::UnsupportedScheme,
                "this endpoint is for servers signing as themselves: use scheme=jwks_uri",
            );
            e.detail.push_str(" (Accept-Signature-Scheme: jwks_uri)");
            let mut api = ApiError::from_sig_error(e);
            api.headers.retain(|(n, _)| *n != "accept-signature-scheme");
            api.headers
                .push(("accept-signature-scheme", "jwks_uri".into()));
            return Err(api);
        }
    };
    aauth_core::ident::validate_server_identifier(&id, app.cfg.insecure_dev_mode).map_err(
        |_| {
            sig_err(
                SigErrorCode::InvalidKey,
                "Signature-Key id is not a valid server identifier",
            )
        },
    )?;
    if !matches!(
        dwk.as_str(),
        "aauth-agent.json" | "aauth-person.json" | "aauth-access.json" | "aauth-resource.json"
    ) {
        return Err(sig_err(
            SigErrorCode::InvalidKey,
            "Signature-Key dwk is not an AAuth metadata document",
        ));
    }
    if id == app.cfg.issuer {
        // Ourselves: resolve locally, never fetch our own metadata.
        let key = app.keys.find_public(&kid).ok_or_else(|| {
            sig_err(
                SigErrorCode::UnknownKey,
                "kid is not one of this server's keys",
            )
        })?;
        sig::verify_parsed(&parsed, key).map_err(ApiError::from_sig_error)?;
    } else {
        let key = app
            .jwks_cache
            .get_key(&id, &dwk, &kid)
            .await
            .map_err(ApiError::from_sig_error)?;
        if let Err(e) = sig::verify_parsed(&parsed, &key) {
            // Silent re-keying: refresh once and retry.
            let key = app
                .jwks_cache
                .refresh_and_get(&id, &dwk, &kid)
                .await
                .map_err(|_| ApiError::from_sig_error(e.clone()))?;
            sig::verify_parsed(&parsed, &key).map_err(ApiError::from_sig_error)?;
        }
    }
    if body {
        verify_content_digest(ctx)?;
    }
    if body
        && !app
            .replay
            .check_and_insert(&kid, &parsed.signature, app.cfg.signature_window_secs)
    {
        return Err(sig_err(
            SigErrorCode::InvalidSignature,
            "signature replayed: this exact signature was already accepted inside the window",
        ));
    }
    Ok(ServerSigner { id, dwk, kid })
}

/// Verify a compact agent token issued by *some* Agent Provider (§Agent Token
/// Verification): `typ`, `dwk`, valid `iss`, JWKS discovery by `kid`,
/// signature (with one refresh-and-retry on failure), `exp`/`iat`, claim
/// structure. Errors are signature-layer errors (`401`) because the token
/// arrived in `Signature-Key`.
pub async fn verify_foreign_agent_token(
    app: &Arc<App>,
    token: &str,
    now: u64,
) -> Result<tokens::AgentTokenClaims, ApiError> {
    let decoded = jwt::decode(token)
        .map_err(|_| sig_err(SigErrorCode::InvalidJwt, "malformed agent token"))?;
    if decoded.header.typ.as_deref() != Some(tokens::TYP_AGENT) {
        return Err(sig_err(
            SigErrorCode::InvalidJwt,
            format!(
                "Signature-Key JWT typ is {:?}; a PS endpoint requires an agent token \
                 ({})",
                decoded.header.typ,
                tokens::TYP_AGENT
            ),
        ));
    }
    let kid = decoded
        .header
        .kid
        .as_deref()
        .ok_or_else(|| sig_err(SigErrorCode::InvalidJwt, "agent token has no kid"))?;
    let iss = decoded
        .payload
        .str_claim("iss")
        .ok_or_else(|| sig_err(SigErrorCode::InvalidJwt, "agent token has no iss"))?;
    aauth_core::ident::validate_server_identifier(iss, app.cfg.insecure_dev_mode).map_err(
        |_| {
            sig_err(
                SigErrorCode::InvalidJwt,
                "agent token iss is not a valid server identifier",
            )
        },
    )?;
    let dwk = decoded.payload.str_claim("dwk").unwrap_or("");
    if dwk != "aauth-agent.json" {
        return Err(sig_err(
            SigErrorCode::InvalidJwt,
            "agent token dwk is not aauth-agent.json",
        ));
    }
    // Cheap temporal checks before any network fetch.
    match decoded.payload.int_claim("exp") {
        Some(exp) if exp > now as i64 => {}
        Some(_) => return Err(sig_err(SigErrorCode::ExpiredJwt, "agent token expired")),
        None => return Err(sig_err(SigErrorCode::InvalidJwt, "agent token has no exp")),
    }

    verify_jwt_via_discovery(app, &decoded, iss, dwk, kid)
        .await
        .map_err(ApiError::from_sig_error)?;
    tokens::validate_agent_token(&decoded, now, app.cfg.insecure_dev_mode).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("expired") {
            sig_err(SigErrorCode::ExpiredJwt, msg)
        } else {
            sig_err(SigErrorCode::InvalidJwt, msg)
        }
    })
}

/// Verify a decoded JWT's signature against a key discovered from
/// `{iss}/.well-known/{dwk}` by `kid`, with the once-refresh-and-retry of
/// §JWKS Discovery on failure. Shared by agent-token, resource-token and
/// (later) auth-token verification; the caller maps the `SigError` to its
/// endpoint's error vocabulary.
pub async fn verify_jwt_via_discovery(
    app: &Arc<App>,
    decoded: &jwt::DecodedJwt,
    iss: &str,
    dwk: &str,
    kid: &str,
) -> Result<(), SigError> {
    let key = app.jwks_cache.get_key(iss, dwk, kid).await?;
    match jwt::verify_with_jwk(decoded, &key) {
        Ok(()) => Ok(()),
        Err(jwt::JwtError::UnsupportedAlgorithm) => Err(SigError::new(
            SigErrorCode::UnsupportedAlgorithm,
            "token alg is not Ed25519",
        )),
        Err(_) => {
            // Silent re-keying under the same kid: refresh once and retry
            // (subject to the fetch floor). If the refresh cannot happen
            // (floor active, network) the key we hold failed → invalid_jwt;
            // if the refreshed JWKS no longer has the kid → unknown_key.
            match app.jwks_cache.refresh_and_get(iss, dwk, kid).await {
                Ok(key) => jwt::verify_with_jwk(decoded, &key).map_err(|_| {
                    SigError::new(SigErrorCode::InvalidJwt, "token signature invalid")
                }),
                Err(e)
                    if e.code == SigErrorCode::UnknownKey
                        && !e.detail.contains(crate::jwks_cache::FLOOR_NOTE) =>
                {
                    Err(e)
                }
                Err(_) => Err(SigError::new(
                    SigErrorCode::InvalidJwt,
                    "token signature invalid",
                )),
            }
        }
    }
}

/// RFC 9530: parse `Content-Digest` (a Dictionary of algorithm → byte
/// sequence) and require every recognised member to match the body. At least
/// one recognised algorithm (`sha-256`, `sha-512`) must be present.
fn verify_content_digest(ctx: &ReqCtx) -> Result<(), ApiError> {
    let value = ctx.header("content-digest").ok_or_else(|| {
        sig_err(
            SigErrorCode::InvalidSignature,
            "Content-Digest header missing on a request with a body",
        )
    })?;
    let dict = aauth_core::sfv::parse_dictionary(&value).map_err(|e| {
        sig_err(
            SigErrorCode::InvalidSignature,
            format!("Content-Digest is not a valid structured field: {e}"),
        )
    })?;
    let mut recognised = 0;
    for (alg, member) in &dict {
        let bytes = match &member.value {
            aauth_core::sfv::MemberValue::Item(item, _) => item.as_bytes(),
            _ => None,
        };
        let expected: Option<Vec<u8>> = match alg.as_str() {
            "sha-256" => Some(Sha256::digest(&ctx.body).to_vec()),
            "sha-512" => Some(Sha512::digest(&ctx.body).to_vec()),
            _ => None,
        };
        if let Some(expected) = expected {
            recognised += 1;
            let ok = matches!(bytes, Some(b) if b == expected.as_slice());
            if !ok {
                return Err(sig_err(
                    SigErrorCode::InvalidSignature,
                    format!("Content-Digest {alg} does not match the request body"),
                ));
            }
        }
    }
    if recognised == 0 {
        return Err(sig_err(
            SigErrorCode::InvalidSignature,
            "Content-Digest carries no sha-256 or sha-512 member",
        ));
    }
    Ok(())
}

/// The `Content-Digest` header value for a body (sha-256), for our own
/// outbound signed POSTs and for tests.
pub fn content_digest_sha256(body: &[u8]) -> String {
    format!(
        "sha-256=:{}:",
        aauth_core::b64::encode_std(&Sha256::digest(body))
    )
}

/// Short-lived replay guard (§Freshness and Replay): remembers every accepted
/// signature, keyed by `(jkt, signature bytes)`, for the duration of the
/// window. A replay carries the very same bytes; two distinct requests never
/// do (their covered components differ). In-memory and per-process: it bounds
/// replay of a captured signature to a single instance, which is the guarantee
/// the draft describes.
pub struct ReplayCache {
    seen: std::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache {
    pub fn new() -> ReplayCache {
        ReplayCache {
            seen: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Returns `true` if the signature is new (and records it), `false` if it
    /// was already seen. Entries older than the window are dropped on the way.
    pub fn check_and_insert(&self, jkt: &str, signature: &[u8], window_secs: u64) -> bool {
        let now = aauth_core::now_unix();
        // A digest of (jkt, signature) keeps the key small and fixed-size.
        let key = {
            let mut h = Sha256::new();
            h.update(jkt.as_bytes());
            h.update([0u8]);
            h.update(signature);
            aauth_core::b64::encode(&h.finalize())
        };
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, inserted| now.saturating_sub(*inserted) <= window_secs);
        if seen.contains_key(&key) {
            return false;
        }
        seen.insert(key, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_cache_rejects_duplicates_only() {
        let c = ReplayCache::new();
        assert!(c.check_and_insert("k", b"sig-a", 60));
        assert!(!c.check_and_insert("k", b"sig-a", 60));
        assert!(c.check_and_insert("k", b"sig-b", 60));
        assert!(c.check_and_insert("k2", b"sig-a", 60));
    }

    #[test]
    fn content_digest_rfc9530_vector() {
        // RFC 9530 §B: sha-256 of `{"hello": "world"}`.
        assert_eq!(
            content_digest_sha256(br#"{"hello": "world"}"#),
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
        );
    }

    fn ctx_with_digest(body: &[u8], digest: &str) -> ReqCtx {
        ReqCtx {
            method: "POST".into(),
            authority: "ps.example".into(),
            path: "/person".into(),
            query: String::new(),
            headers: vec![("content-digest".into(), digest.into())],
            body: body.to_vec(),
        }
    }

    #[test]
    fn content_digest_verification() {
        let body = br#"{"hello": "world"}"#;
        verify_content_digest(&ctx_with_digest(body, &content_digest_sha256(body))).unwrap();
        // sha-512 (RFC 9421 test request) is accepted too
        verify_content_digest(&ctx_with_digest(
            body,
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        ))
        .unwrap();
        // tampered body
        let err = verify_content_digest(&ctx_with_digest(
            br#"{"hello": "there"}"#,
            &content_digest_sha256(body),
        ))
        .unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.error, "invalid_signature");
        // unknown algorithm only
        assert!(verify_content_digest(&ctx_with_digest(body, "md5=:AAAA:")).is_err());
        // a bad member alongside a good one still fails
        assert!(verify_content_digest(&ctx_with_digest(
            body,
            &format!("{}, sha-512=:AAAA:", content_digest_sha256(body))
        ))
        .is_err());
    }
}
