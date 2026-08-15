//! Four-party: federating with a resource's Access Server (§Access Server
//! Federation, §PS-AS Federation, §Auth Token Delivery).
//!
//! When a resource token's `aud` names an Access Server rather than us, the
//! person's consent is still ours to obtain; the resource's *policy* is the
//! AS's. We POST the resource token and the agent token to the AS's
//! `auth_token_endpoint`, signed as ourselves, and follow the deferred loop:
//! `202 requirement=claims` is answered here (the only claim we assert is the
//! directed `sub`); `interaction`, `approval` and `clarification` are handed
//! back to the agent through a pending record whose polls poll the AS; `402`
//! is refused (no billing relationship). An auth token the AS issues is
//! verified before it is returned — `iss`, `aud`, `cnf`, `sub`, `scope` —
//! and recorded as *provided* so a later revocation can reach the resource.
//!
//! No live Access Server exists in the ecosystem: this is exercised against
//! a mock only, and the README says so.

use std::sync::Arc;

use aauth_core::jwk::Jwk;
use aauth_core::jwt::{self, ClaimExt};
use aauth_core::{sig, sigkey, tokens};
use hyper::StatusCode;

use crate::app::App;
use crate::httpc::{self, HttpResponse};
use crate::problem::ApiError;
use crate::reqctx;

/// What we send the AS.
pub struct FederationRequest<'a> {
    pub resource_token: &'a str,
    pub agent_token: &'a str,
    pub subagent_token: Option<&'a str>,
    pub upstream_token: Option<&'a str>,
}

/// What the AS's auth token must say (§Auth Token Delivery), carried on the
/// pending record across polls.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Expect {
    pub as_iss: String,
    pub resource: String,
    pub cnf_jwk: Jwk,
    pub sub: String,
    pub requested_scope: Option<String>,
}

/// One turn of the deferred loop with the AS.
pub enum Outcome {
    /// The AS issued a token that verified.
    Token {
        token: String,
        jti: String,
        exp: u64,
    },
    /// The AS needs something the agent (or its user) must do.
    Deferred {
        location: String,
        requirement: Option<String>,
        body: serde_json::Value,
    },
}

/// Bounded number of `requirement=claims` rounds answered inline.
const MAX_CLAIMS_ROUNDS: usize = 5;

fn as_error(detail: impl Into<String>) -> ApiError {
    ApiError::new(
        StatusCode::BAD_GATEWAY,
        "server_error",
        format!("access server: {}", detail.into()),
    )
}

/// The AS's `auth_token_endpoint`, discovered and issuer-checked.
async fn token_endpoint(app: &Arc<App>, as_iss: &str) -> Result<String, ApiError> {
    let meta = app
        .jwks_cache
        .get_metadata(as_iss, "aauth-access.json")
        .await
        .map_err(|e| e.into_api(|s| as_error(format!("metadata for {as_iss}: {s}"))))?;
    let ep = meta
        .get("auth_token_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| as_error("metadata has no auth_token_endpoint"))?;
    if !(ep.starts_with("https://") || (app.cfg.insecure_dev_mode && ep.starts_with("http://"))) {
        return Err(as_error("auth_token_endpoint is not https"));
    }
    if ep.contains('?') || ep.contains('#') {
        return Err(as_error(
            "auth_token_endpoint must not carry a query or fragment",
        ));
    }
    Ok(ep.to_string())
}

/// A request to `url` signed by us as ourselves (`jwks_uri`, our active kid),
/// covering `content-type`+`content-digest` when there is a body.
async fn signed(
    app: &Arc<App>,
    method: &str,
    url: &str,
    body: Option<&serde_json::Value>,
    prefer_wait: Option<u64>,
) -> Result<HttpResponse, ApiError> {
    let (authority, path) = httpc::signing_parts(url).map_err(as_error)?;
    let body_bytes = body.map(|b| b.to_string().into_bytes());
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut extra: Vec<&str> = Vec::new();
    if let Some(b) = &body_bytes {
        headers.push(("content-type".into(), "application/json".into()));
        headers.push(("content-digest".into(), reqctx::content_digest_sha256(b)));
        extra = vec!["content-type", "content-digest"];
    }
    let for_sig = headers.clone();
    let lookup = move |name: &str| {
        for_sig
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    let scheme =
        sigkey::serialize_jwks_uri(&app.cfg.issuer, "aauth-person.json", &app.keys.active_kid);
    let s = sig::sign_request(
        method,
        &authority,
        &path,
        "",
        &extra,
        &lookup,
        &scheme,
        &app.keys.active_key,
        aauth_core::now_unix(),
    )
    .map_err(|e| ApiError::server_error(format!("sign: {e}")))?;
    headers.push(("signature-input".into(), s.signature_input));
    headers.push(("signature".into(), s.signature));
    headers.push(("signature-key".into(), s.signature_key));
    if let Some(w) = prefer_wait {
        headers.push(("prefer".into(), format!("wait={w}")));
    }
    // Content-type is set by httpc for bodies; do not send it twice.
    let send_headers: Vec<(String, String)> = headers
        .into_iter()
        .filter(|(n, _)| n != "content-type")
        .collect();
    httpc::request(
        method,
        url,
        &send_headers,
        body_bytes.as_deref(),
        &app.egress,
    )
    .await
    .map_err(as_error)
}

/// Start federation: POST to the AS and run the loop until a token, a
/// deferral the agent must act on, or an error.
pub async fn start(
    app: &Arc<App>,
    req: &FederationRequest<'_>,
    expect: &Expect,
) -> Result<Outcome, ApiError> {
    let ep = token_endpoint(app, &expect.as_iss).await?;
    let mut body = serde_json::json!({
        "resource_token": req.resource_token,
        "agent_token": req.agent_token,
    });
    if let Some(s) = req.subagent_token {
        body["subagent_token"] = s.into();
    }
    if let Some(u) = req.upstream_token {
        body["upstream_token"] = u.into();
    }
    let resp = signed(app, "POST", &ep, Some(&body), None).await?;
    handle(app, resp, expect, 0).await
}

/// Poll the AS's pending URL for a deferred request (signed GET).
pub async fn poll(
    app: &Arc<App>,
    location: &str,
    expect: &Expect,
    wait: Option<u64>,
) -> Result<Outcome, ApiError> {
    if !(location.starts_with("https://")
        || (app.cfg.insecure_dev_mode && location.starts_with("http://")))
    {
        return Err(as_error("pending URL is not https"));
    }
    let resp = signed(app, "GET", location, None, wait).await?;
    handle(app, resp, expect, 0).await
}

/// Interpret one AS response.
async fn handle(
    app: &Arc<App>,
    resp: HttpResponse,
    expect: &Expect,
    claims_rounds: usize,
) -> Result<Outcome, ApiError> {
    match resp.status {
        200 => {
            let v = resp.json();
            let token = v
                .get("auth_token")
                .and_then(|t| t.as_str())
                .ok_or_else(|| as_error("200 without auth_token"))?;
            let (jti, exp) = verify_as_auth_token(app, token, expect).await?;
            Ok(Outcome::Token {
                token: token.to_string(),
                jti,
                exp,
            })
        }
        202 => {
            let location = resp
                .header("location")
                .ok_or_else(|| as_error("202 without Location"))?
                .to_string();
            let requirement = resp.header("aauth-requirement").map(String::from);
            let body = resp.json();
            let name = requirement.as_deref().and_then(requirement_name);
            if name.as_deref() == Some("claims") {
                // The only identity claim we assert is the directed `sub`
                // (already the resource token's); anything else the AS asks
                // for we do not have and it may decide accordingly.
                if claims_rounds >= MAX_CLAIMS_ROUNDS {
                    return Err(as_error("too many claims rounds"));
                }
                let claims = serde_json::json!({ "sub": expect.sub });
                let next = signed(app, "POST", &location, Some(&claims), None).await?;
                return Box::pin(handle(app, next, expect, claims_rounds + 1)).await;
            }
            Ok(Outcome::Deferred {
                location,
                requirement,
                body,
            })
        }
        402 => Err(ApiError::forbidden(
            "user_unreachable",
            "the access server requires a billing relationship this person server does not \
             have; the request cannot proceed",
        )),
        403 => {
            let v = resp.json();
            Err(ApiError::forbidden(
                v.get("error").and_then(|e| e.as_str()).unwrap_or("denied"),
                format!(
                    "the access server refused: {}",
                    v.get("detail").and_then(|d| d.as_str()).unwrap_or("")
                ),
            ))
        }
        s @ (400 | 404 | 408 | 410) => {
            let v = resp.json();
            Err(ApiError::new(
                StatusCode::from_u16(s).unwrap_or(StatusCode::BAD_REQUEST),
                v.get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("invalid_request"),
                format!(
                    "the access server answered {s}: {}",
                    v.get("detail").and_then(|d| d.as_str()).unwrap_or("")
                ),
            ))
        }
        s => Err(as_error(format!("unexpected HTTP {s}"))),
    }
}

/// The `requirement` token of an `AAuth-Requirement` header value.
pub fn requirement_name(header: &str) -> Option<String> {
    let dict = aauth_core::sfv::parse_dictionary(header).ok()?;
    dict.iter()
        .find(|(k, _)| k == "requirement")
        .and_then(|(_, m)| match &m.value {
            aauth_core::sfv::MemberValue::Item(item, _) => item.as_str().map(String::from),
            _ => None,
        })
}

/// §Auth Token Delivery: verify what the AS issued before handing it on.
async fn verify_as_auth_token(
    app: &Arc<App>,
    token: &str,
    expect: &Expect,
) -> Result<(String, u64), ApiError> {
    let decoded = jwt::decode(token).map_err(|_| as_error("auth token is not a JWT"))?;
    if decoded.header.typ.as_deref() != Some(tokens::TYP_AUTH) {
        return Err(as_error("auth token typ is not aa-auth+jwt"));
    }
    let p = &decoded.payload;
    let s = |n: &str| p.str_claim(n).map(String::from);
    if s("iss").as_deref() != Some(expect.as_iss.as_str()) {
        return Err(as_error(
            "auth token iss is not the access server we called",
        ));
    }
    if s("dwk").as_deref() != Some("aauth-access.json") {
        return Err(as_error("auth token dwk is not aauth-access.json"));
    }
    let kid = decoded
        .header
        .kid
        .as_deref()
        .ok_or_else(|| as_error("auth token has no kid"))?;
    reqctx::verify_jwt_via_discovery(app, &decoded, &expect.as_iss, "aauth-access.json", kid)
        .await
        .map_err(|e| e.into_api(|s| as_error(format!("auth token signature: {s}"))))?;
    let now = aauth_core::now_unix() as i64;
    let exp = p
        .int_claim("exp")
        .ok_or_else(|| as_error("auth token has no exp"))?;
    if exp <= now {
        return Err(as_error("auth token already expired"));
    }
    if p.int_claim("iat").unwrap_or(0) > now + 60 {
        return Err(as_error("auth token iat in the future"));
    }
    if s("aud").as_deref() != Some(expect.resource.as_str()) {
        return Err(as_error("auth token aud is not the resource"));
    }
    let cnf: Option<Jwk> = p
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .and_then(|j| serde_json::from_value(j.clone()).ok());
    match cnf {
        Some(k) if k.public_only().x == expect.cnf_jwk.public_only().x => {}
        _ => return Err(as_error("auth token cnf.jwk is not the agent's key")),
    }
    if s("sub").as_deref() != Some(expect.sub.as_str()) {
        return Err(as_error(
            "auth token sub is not the directed identifier we issued",
        ));
    }
    if let Some(scope) = s("scope") {
        let requested: std::collections::BTreeSet<&str> = expect
            .requested_scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        let granted: std::collections::BTreeSet<&str> = scope.split_whitespace().collect();
        if !granted.is_subset(&requested) {
            return Err(as_error("auth token scope is broader than requested"));
        }
    }
    let jti = s("jti").ok_or_else(|| as_error("auth token has no jti"))?;
    Ok((jti, exp as u64))
}
