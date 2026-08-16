//! Resource token verification at the PS (§Resource Token Verification), the
//! seven steps in order — including step 6, the one comparing claims alone
//! cannot do: resolve `presented_jti` against our **retained** person-token
//! records, refuse an unknown one with `unknown_person_token`, and treat a
//! mismatch against an existing record as evidence of tampering (mission
//! stripping) that is **surfaced to operators**, not merely rejected.
//!
//! Errors use the token-endpoint vocabulary (`invalid_resource_token`,
//! `expired_resource_token`, `unknown_person_token`; all 400): the resource
//! token is a body parameter, not the Signature-Key material.

use std::sync::Arc;

use aauth_core::jwk::Jwk;
use aauth_core::jwt::{self, ClaimExt};
use aauth_core::tokens;

use crate::app::App;
use crate::problem::ApiError;
use crate::reqctx::{self, AgentSigner};
use crate::store::PersonTokenRecord;

/// A verified resource token and the retained record it named.
#[derive(Debug, Clone)]
pub struct VerifiedResourceToken {
    /// The resource (`iss`) — becomes the auth token's `aud`.
    pub resource: String,
    /// `Some(as_url)` when `aud` names an Access Server (four-party); `None`
    /// when `aud` is this PS (three-party).
    pub access_server: Option<String>,
    pub jti: String,
    pub sub: String,
    pub presented_jti: String,
    pub scope: Option<String>,
    pub account: Option<String>,
    pub mission_s256: Option<String>,
    pub tenant: Option<String>,
    pub exp: u64,
    pub record: PersonTokenRecord,
}

fn invalid(detail: impl Into<String>) -> ApiError {
    ApiError::bad_request("invalid_resource_token", detail)
}

/// Verify `token` presented by `signer` (whose key — or, parent-mediated,
/// `subagent_cnf` — must be the token's `agent_jkt`).
pub async fn verify(
    app: &Arc<App>,
    token: &str,
    signer: &AgentSigner,
    subagent_cnf: Option<&Jwk>,
) -> Result<VerifiedResourceToken, ApiError> {
    let now = aauth_core::now_unix();
    let decoded = jwt::decode(token).map_err(|_| invalid("resource token is not a JWT"))?;
    // 1. typ
    if decoded.header.typ.as_deref() != Some(tokens::TYP_RESOURCE) {
        return Err(invalid(format!(
            "typ is {:?}, expected {}",
            decoded.header.typ,
            tokens::TYP_RESOURCE
        )));
    }
    let p = &decoded.payload;
    let str_claim = |name: &str| p.str_claim(name).map(|s| s.to_string());
    // 2. dwk + discovery + signature
    let iss = str_claim("iss").ok_or_else(|| invalid("missing iss"))?;
    aauth_core::ident::validate_server_identifier(&iss, app.cfg.insecure_dev_mode)
        .map_err(|_| invalid("iss is not a valid server identifier"))?;
    if p.str_claim("dwk") != Some("aauth-resource.json") {
        return Err(invalid("dwk is not aauth-resource.json"));
    }
    let kid = decoded
        .header
        .kid
        .as_deref()
        .ok_or_else(|| invalid("missing kid"))?;
    reqctx::verify_jwt_via_discovery(app, &decoded, &iss, "aauth-resource.json", kid)
        .await
        .map_err(|e| e.into_api(|s| invalid(format!("signature not verified: {s}"))))?;
    // 3. exp / iat, and the lifetime we accept
    let exp = p.int_claim("exp").ok_or_else(|| invalid("missing exp"))?;
    let iat = p.int_claim("iat").ok_or_else(|| invalid("missing iat"))?;
    if exp <= now as i64 {
        return Err(ApiError::bad_request(
            "expired_resource_token",
            "the resource token expired; obtain a new resource token from the resource and retry",
        ));
    }
    if iat > now as i64 + 60 {
        return Err(invalid("iat is in the future"));
    }
    if exp - iat > app.cfg.resource_token_max_age_secs as i64 {
        return Err(invalid(format!(
            "lifetime {}s exceeds the {}s this person server accepts",
            exp - iat,
            app.cfg.resource_token_max_age_secs
        )));
    }
    // 4. aud is us (three-party), or — with federation enabled — the Access
    //    Server we will call (four-party; the AS checks aud against itself).
    let access_server = match p.str_claim("aud") {
        Some(a) if a == app.cfg.issuer => None,
        Some(a) if app.cfg.federation.enabled => {
            aauth_core::ident::validate_server_identifier(a, app.cfg.insecure_dev_mode)
                .map_err(|_| invalid("aud is not a valid server identifier"))?;
            Some(a.to_string())
        }
        Some(a) => {
            return Err(ApiError::bad_request(
                "invalid_request",
                format!(
                    "resource token aud is {a}, not this person server; four-party (Access \
                     Server) federation is not enabled on this person server"
                ),
            ))
        }
        None => return Err(invalid("missing aud")),
    };
    // 5. agent_jkt is the key that signed the request (or the sub-agent's).
    let expected_jkt = match subagent_cnf {
        Some(k) => k
            .thumbprint()
            .map_err(|_| ApiError::server_error("subagent key has no thumbprint"))?,
        None => signer.jkt.clone(),
    };
    match p.str_claim("agent_jkt") {
        Some(j) if j == expected_jkt => {}
        Some(_) => {
            return Err(invalid(
                "agent_jkt does not match the key that signed this request",
            ))
        }
        None => return Err(invalid("missing agent_jkt")),
    }
    // Resource-initiated interaction: not built yet — fail closed.
    if p.get("interaction").is_some() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "resource-initiated interaction is not supported by this person server (the resource \
             token carries an interaction claim)",
        ));
    }
    // 6. presented_jti → retained record, exact match on ps/sub/mission/tenant.
    //    `person_token_jti` is the claim's name before -11 renamed it
    //    (§Document History: "Renamed the resource token claim
    //    person_token_jti to presented_jti … The value is unchanged"), and
    //    the one live resource today (whoami.aauth.dev) still emits it.
    //    Same value, same check; accepting the old name costs nothing and
    //    turns a wire-level rename into interop instead of a refusal.
    let presented_jti = str_claim("presented_jti")
        .or_else(|| str_claim("person_token_jti"))
        .ok_or_else(|| invalid("missing presented_jti"))?;
    let record = app
        .store
        .person_token_record(&presented_jti)?
        .ok_or_else(|| {
            ApiError::bad_request(
            "unknown_person_token",
            "presented_jti names no person token this server retains (tampered, another server's, \
             or outside the retention window)",
        )
        })?;
    let ps = str_claim("ps");
    let sub = str_claim("sub");
    let mission_s256 = str_claim("mission_s256");
    let tenant = str_claim("tenant");
    let mut mismatches: Vec<&str> = Vec::new();
    if ps.as_deref() != Some(record.ps.as_str()) {
        mismatches.push("ps");
    }
    if sub.as_deref() != Some(record.sub.as_str()) {
        mismatches.push("sub");
    }
    if mission_s256 != record.mission_s256 {
        mismatches.push("mission_s256");
    }
    if tenant != record.tenant {
        mismatches.push("tenant");
    }
    // Defensive, beyond the listed four: the token must come from the resource
    // the person token was issued to, from the agent it was issued for.
    if iss != record.aud {
        mismatches.push("iss≠record.aud");
    }
    let (a_iss, a_sub) = signer.agent();
    if a_iss != record.agent_iss || a_sub != record.agent_sub {
        mismatches.push("agent≠record.agent");
    }
    if !mismatches.is_empty() {
        // Evidence of tampering — surface to operators, then reject.
        app.record(
            Some(&record.person_id),
            &format!("agent:{a_sub}"),
            "resource_token_mismatch",
            Some(&iss),
            serde_json::json!({
                "severity": "warning",
                "presented_jti": presented_jti,
                "resource_jti": str_claim("jti"),
                "mismatched": mismatches,
                "token": { "ps": ps, "sub": sub, "mission_s256": mission_s256, "tenant": tenant, "iss": iss },
                "record": { "ps": record.ps, "sub": record.sub, "mission_s256": record.mission_s256,
                            "tenant": record.tenant, "aud": record.aud, "agent_iss": record.agent_iss,
                            "agent_sub": record.agent_sub },
                "note": "a mismatch against a retained record is evidence of tampering such as mission stripping",
            }),
        );
        return Err(invalid(format!(
            "claims do not match the retained record of the named person token ({})",
            mismatches.join(", ")
        )));
    }
    // 7. mission_s256 present → the mission must be active. Records never
    //    carry one while missions are unsupported, so step 6 already refused it.
    Ok(VerifiedResourceToken {
        resource: iss,
        access_server,
        jti: str_claim("jti").ok_or_else(|| invalid("missing jti"))?,
        sub: sub.unwrap_or_default(),
        presented_jti,
        scope: str_claim("scope"),
        account: str_claim("account"),
        mission_s256,
        tenant,
        exp: exp as u64,
        record,
    })
}
