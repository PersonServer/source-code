//! Call chaining (§Call Chaining, §Upstream Token Verification): a resource
//! that received an auth token acts as an agent downstream and brings that
//! token as `upstream_token`. We then issue **for the person the upstream
//! token was issued for**, found from its `sub` — which this PS must have
//! issued — never for whoever is bound to the intermediary. An intermediary
//! acts for many people, so it is never bound to one; its identity is its own
//! agent token (a resource acting as an agent publishes agent metadata and
//! signs as itself).

use std::sync::Arc;

use aauth_core::jwt::{self, ClaimExt};
use aauth_core::tokens;

use crate::app::App;
use crate::problem::ApiError;
use crate::reqctx::{self, AgentSigner};

/// A verified upstream token and the person it names.
#[derive(Debug, Clone)]
pub struct Upstream {
    pub iss: String,
    pub jti: String,
    /// The intermediary the token was issued to (its `aud`) — equal to the
    /// signing agent's `iss`, i.e. the intermediary is its own Agent Provider.
    pub aud: String,
    pub sub: String,
    pub scope: Option<String>,
    pub mission_s256: Option<String>,
    pub tenant: Option<String>,
    /// The person behind `sub`, resolved from our directed-sub records.
    pub person_id: String,
}

fn invalid(detail: impl Into<String>) -> ApiError {
    ApiError::bad_request(
        "invalid_request",
        format!("upstream_token: {}", detail.into()),
    )
}

/// Verify `upstream_token` presented by `signer` (the intermediary).
pub async fn verify(
    app: &Arc<App>,
    token: &str,
    signer: &AgentSigner,
) -> Result<Upstream, ApiError> {
    let now = aauth_core::now_unix();
    let decoded = jwt::decode(token).map_err(|_| invalid("not a JWT"))?;
    // 1. Auth token verification — JWT trust.
    if decoded.header.typ.as_deref() != Some(tokens::TYP_AUTH) {
        return Err(invalid(format!(
            "typ is {:?}, expected {}",
            decoded.header.typ,
            tokens::TYP_AUTH
        )));
    }
    let p = &decoded.payload;
    let s = |n: &str| p.str_claim(n).map(|v| v.to_string());
    let iss = s("iss").ok_or_else(|| invalid("missing iss"))?;
    aauth_core::ident::validate_server_identifier(&iss, app.cfg.insecure_dev_mode)
        .map_err(|_| invalid("iss is not a valid server identifier"))?;
    let dwk = s("dwk").unwrap_or_default();
    if dwk != "aauth-person.json" && dwk != "aauth-access.json" {
        return Err(invalid(
            "dwk is neither aauth-person.json nor aauth-access.json",
        ));
    }
    let kid = decoded
        .header
        .kid
        .as_deref()
        .ok_or_else(|| invalid("missing kid"))?;
    if iss == app.cfg.issuer {
        let key = app
            .keys
            .find_public(kid)
            .ok_or_else(|| invalid("kid is not one of this server's keys"))?;
        jwt::verify_with_jwk(&decoded, key).map_err(|_| invalid("signature not verified"))?;
    } else {
        reqctx::verify_jwt_via_discovery(app, &decoded, &iss, &dwk, kid)
            .await
            .map_err(|e| invalid(format!("signature not verified: {e}")))?;
    }
    let exp = p.int_claim("exp").ok_or_else(|| invalid("missing exp"))?;
    if exp <= now as i64 {
        return Err(invalid("expired"));
    }
    if p.int_claim("iat").unwrap_or(0) > now as i64 + 60 {
        return Err(invalid("iat is in the future"));
    }
    let jti = s("jti").ok_or_else(|| invalid("missing jti"))?;
    let aud = s("aud").ok_or_else(|| invalid("missing aud"))?;
    let sub = s("sub").ok_or_else(|| invalid("missing sub (REQUIRED in auth tokens)"))?;
    // 2. A trusted issuer: ourselves, or an Access Server whose token we
    //    brokered — either way the token is one we recorded.
    let rec = app
        .store
        .auth_token_record(&jti)?
        .filter(|r| r.iss.as_deref().unwrap_or(app.cfg.issuer.as_str()) == iss);
    let Some(rec) = rec else {
        return Err(invalid(
            "issuer is not this server nor an Access Server whose token this server provided",
        ));
    };
    if rec.revoked_at.is_some() {
        return Err(invalid("the upstream authorization was revoked"));
    }
    // 3. The token was issued to the intermediary now making the request:
    //    its `aud` equals the `iss` of the intermediary's agent token.
    if aud != signer.claims.iss {
        return Err(invalid(
            "aud does not equal the requesting agent's issuer; the upstream token was not issued \
             to this intermediary",
        ));
    }
    // The person: from `sub`, which we issued for exactly this audience.
    let (person_id, audience) = app
        .store
        .person_for_sub(&sub)?
        .ok_or_else(|| invalid("sub was not issued by this server"))?;
    if audience != aud || rec.sub != sub || rec.aud != aud {
        return Err(invalid(
            "sub/aud do not match this server's record of the token",
        ));
    }
    Ok(Upstream {
        iss,
        jti,
        aud,
        sub,
        scope: s("scope"),
        mission_s256: s("mission_s256"),
        tenant: s("tenant"),
        person_id,
    })
}
