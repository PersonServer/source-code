//! Minting person tokens (§Person Token Structure) and auth tokens (§Auth
//! Token Structure), and keeping the record (§Person Token Endpoint retention;
//! auth-token records for revocation).
//!
//! One function per token type does the whole obligation: derive/lookup the
//! directed `sub`, sign, retain — so no code path can issue without retaining.

use aauth_core::jwk::Jwk;
use aauth_core::{jwt, tokens};

use crate::app::App;
use crate::problem::ApiError;
use crate::store::{AuthTokenRecord, PersonTokenRecord};

/// What a person token is issued for.
pub struct PersonTokenRequest<'a> {
    pub person_id: &'a str,
    /// The requesting agent — the one bound to the person and named in the
    /// retained record (for a parent-mediated request, the parent).
    pub agent_iss: &'a str,
    pub agent_sub: &'a str,
    /// The key the token is bound to (`cnf.jwk`): the requesting agent's, or
    /// the sub-agent's under `subagent_token`.
    pub cnf_jwk: &'a Jwk,
    /// The resource the token identifies the person to (`aud`).
    pub audience: &'a str,
    /// `exp` of the agent token presented when requesting: the person token
    /// MUST NOT outlive it.
    pub agent_token_exp: u64,
    /// The mission's `expires_at` when operating under one.
    pub mission_expires_at: Option<u64>,
    pub mission_s256: Option<&'a str>,
    /// Organisational context to issue as `tenant`; when `None`, the
    /// person's own tenant (from their identity provider) is used.
    pub tenant: Option<&'a str>,
}

/// An issued person token plus what the agent is told about it.
#[derive(Debug, Clone)]
pub struct IssuedPersonToken {
    pub token: String,
    pub jti: String,
    pub sub: String,
    pub exp: u64,
}

impl IssuedPersonToken {
    pub fn expires_in(&self) -> u64 {
        self.exp.saturating_sub(aauth_core::now_unix())
    }
}

/// Mint and retain a person token. `exp = min(now + ttl, agent_token.exp,
/// mission.expires_at)`; a computed lifetime of zero is refused.
pub fn person_token(app: &App, req: &PersonTokenRequest) -> Result<IssuedPersonToken, ApiError> {
    let now = aauth_core::now_unix();
    let mut exp = now + app.cfg.person_token_ttl_secs;
    exp = exp.min(req.agent_token_exp);
    if let Some(m) = req.mission_expires_at {
        exp = exp.min(m);
    }
    if exp <= now {
        return Err(ApiError::bad_request(
            "invalid_request",
            "the presented agent token (or mission) expires too soon to issue a person token",
        ));
    }
    let sub = app.store.directed_sub(req.person_id, req.audience, || {
        app.keys.derive_sub(req.person_id, req.audience)
    })?;
    let jti = format!("pt-{}", aauth_core::rand_token(128));
    let mut payload = serde_json::json!({
        "iss": app.cfg.issuer,
        "dwk": "aauth-person.json",
        "aud": req.audience,
        "sub": sub,
        "cnf": { "jwk": req.cnf_jwk.public_only() },
        "jti": jti,
        "iat": now,
        "exp": exp,
    });
    if let Some(m) = req.mission_s256 {
        payload["mission_s256"] = m.into();
    }
    // `tenant` is the person's organisational context (§Person Token
    // Structure), never part of the identifier: what the caller says (an
    // upstream token under call chaining), else what the person's identity
    // provider told us at their last sign-in.
    let tenant: Option<String> = match req.tenant {
        Some(t) => Some(t.to_string()),
        None => app.store.get_person(req.person_id)?.and_then(|p| p.tenant),
    };
    if let Some(t) = &tenant {
        payload["tenant"] = t.as_str().into();
    }
    let token = jwt::sign(
        tokens::TYP_PERSON,
        Some(&app.keys.active_kid),
        None,
        &payload,
        &app.keys.active_key,
    );
    // Retain before returning: issuance and retention are one act.
    app.store.record_person_token(&PersonTokenRecord {
        jti: jti.clone(),
        person_id: req.person_id.to_string(),
        agent_iss: req.agent_iss.to_string(),
        agent_sub: req.agent_sub.to_string(),
        ps: app.cfg.issuer.clone(),
        sub: sub.clone(),
        aud: req.audience.to_string(),
        mission_s256: req.mission_s256.map(|s| s.to_string()),
        tenant,
        iat: now,
        exp,
        purge_after: exp + app.cfg.retention_secs(),
    })?;
    Ok(IssuedPersonToken {
        token,
        jti,
        sub,
        exp,
    })
}

/// What an auth token is issued for (three-party: we are the issuer).
pub struct AuthTokenRequest<'a> {
    pub person_id: &'a str,
    pub agent_iss: &'a str,
    pub agent_sub: &'a str,
    /// The key the token is bound to (`cnf.jwk`).
    pub cnf_jwk: &'a Jwk,
    /// The resource (`aud`) — the resource token's `iss`.
    pub audience: &'a str,
    /// The directed `sub` — the value the resource token carried, which step 6
    /// proved equals our retained record.
    pub sub: &'a str,
    /// Space-separated granted scopes.
    pub scope: Option<&'a str>,
    pub account: Option<&'a str>,
    pub mission_s256: Option<&'a str>,
    pub tenant: Option<&'a str>,
    pub agent_token_exp: u64,
    pub mission_expires_at: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct IssuedAuthToken {
    pub token: String,
    pub jti: String,
    pub exp: u64,
}

impl IssuedAuthToken {
    pub fn expires_in(&self) -> u64 {
        self.exp.saturating_sub(aauth_core::now_unix())
    }
}

/// Mint and record an auth token. No agent identifier, no `act`, no
/// delegation chain — the resource enforces against `sub` and `scope` and
/// learns nothing about which agent; `ps` = `iss` because we issued it.
pub fn auth_token(app: &App, req: &AuthTokenRequest) -> Result<IssuedAuthToken, ApiError> {
    let now = aauth_core::now_unix();
    let mut exp = now + app.cfg.auth_token_ttl_secs;
    exp = exp.min(req.agent_token_exp);
    if let Some(m) = req.mission_expires_at {
        exp = exp.min(m);
    }
    if exp <= now {
        return Err(ApiError::bad_request(
            "invalid_request",
            "the presented agent token (or mission) expires too soon to issue an auth token",
        ));
    }
    let jti = format!("at-{}", aauth_core::rand_token(128));
    let mut payload = serde_json::json!({
        "iss": app.cfg.issuer,
        "dwk": "aauth-person.json",
        "aud": req.audience,
        "jti": jti,
        "ps": app.cfg.issuer,
        "sub": req.sub,
        "cnf": { "jwk": req.cnf_jwk.public_only() },
        "iat": now,
        "exp": exp,
    });
    if let Some(s) = req.scope {
        payload["scope"] = s.into();
    }
    if let Some(a) = req.account {
        payload["account"] = a.into();
    }
    if let Some(m) = req.mission_s256 {
        payload["mission_s256"] = m.into();
    }
    if let Some(t) = req.tenant {
        payload["tenant"] = t.into();
    }
    let token = jwt::sign(
        tokens::TYP_AUTH,
        Some(&app.keys.active_kid),
        None,
        &payload,
        &app.keys.active_key,
    );
    app.store.record_auth_token(&AuthTokenRecord {
        jti: jti.clone(),
        iss: None,
        person_id: req.person_id.to_string(),
        agent_iss: req.agent_iss.to_string(),
        agent_sub: req.agent_sub.to_string(),
        aud: req.audience.to_string(),
        sub: req.sub.to_string(),
        scope: req.scope.map(|s| s.to_string()),
        mission_s256: req.mission_s256.map(|s| s.to_string()),
        iat: now,
        exp,
        revoked_at: None,
    })?;
    Ok(IssuedAuthToken { token, jti, exp })
}
