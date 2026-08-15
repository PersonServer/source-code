//! The agent-facing token endpoints: `person_token_endpoint` (`/person`),
//! `auth_token_endpoint` (`/token`, M4) and the deferred-response poll
//! (`/pending/{id}`).
//!
//! `/person` (§Person Token Endpoint):
//! 1. verify the signed request (agent token, HTTP signature, body digest)
//! 2. validate `resource`; refuse `mission_s256` while missions are off and
//!    `upstream_token` until call chaining exists; verify a
//!    `subagent_token` if present (parent-mediated: the token binds to the
//!    sub-agent's key, consent and binding are the parent's)
//! 3. if the agent is bound to a person who already consented to this
//!    resource → mint and answer `200`
//! 4. otherwise create a pending request and answer `202` with
//!    `AAuth-Requirement: requirement=interaction` — the person decides at
//!    `/consent`; the agent polls `/pending/{id}` (signed, agent-bound)
//!
//! Every path that mints goes through [`crate::issue::person_token`], which
//! retains the record before returning.

use std::sync::Arc;

use aauth_core::jwk::Jwk;
use hyper::StatusCode;

use crate::app::App;
use crate::issue::{self, PersonTokenRequest};
use crate::pending;
use crate::problem::{json_ok, ApiError, Resp};
use crate::reqctx::{self, AgentSigner, ReqCtx};

/// Agent-attested display strings on a request (`platform`, `device`),
/// validated per §Agent Token Request. Never a basis for a decision.
pub struct AttestedDisplay {
    pub platform: Option<String>,
    pub device: Option<String>,
}

pub fn attested_display(body: &serde_json::Value) -> Result<AttestedDisplay, ApiError> {
    let platform = match body.get("platform") {
        None => None,
        Some(v) => {
            let s = v.as_str().ok_or_else(|| {
                ApiError::bad_request("invalid_request", "platform must be a string")
            })?;
            if s.is_empty()
                || s.len() > 64
                || !s
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                return Err(ApiError::bad_request(
                    "invalid_request",
                    "platform must be a registry token (alphanumeric, -, _, .)",
                ));
            }
            Some(s.to_string())
        }
    };
    let device = match body.get("device") {
        None => None,
        Some(v) => {
            let s = v.as_str().ok_or_else(|| {
                ApiError::bad_request("invalid_request", "device must be a string")
            })?;
            if s.is_empty() || s.chars().count() > 64 || s.chars().any(|c| c.is_control()) {
                return Err(ApiError::bad_request(
                    "invalid_request",
                    "device must be 1..=64 printable characters",
                ));
            }
            Some(s.to_string())
        }
    };
    Ok(AttestedDisplay { platform, device })
}

/// Verify a `subagent_token` carried in the body (§Parent-Mediated
/// Authorization): a valid agent token whose `parent_agent` names the signing
/// agent, from the same Agent Provider. Errors are the token-endpoint 400s
/// (`invalid_agent_token` / `expired_agent_token`) — the token is a body
/// parameter, not the Signature-Key material — a bad one is a bad request,
/// not a signature failure.
pub async fn verify_subagent_token(
    app: &Arc<App>,
    token: &str,
    signer: &AgentSigner,
) -> Result<aauth_core::tokens::AgentTokenClaims, ApiError> {
    let now = aauth_core::now_unix();
    let claims = reqctx::verify_foreign_agent_token(app, token, now)
        .await
        .map_err(|e| {
            let expired = e.error == "expired_jwt";
            ApiError::bad_request(
                if expired {
                    "expired_agent_token"
                } else {
                    "invalid_agent_token"
                },
                format!("subagent_token: {}", e.detail),
            )
        })?;
    if claims.parent_agent.as_deref() != Some(signer.claims.sub.as_str()) {
        return Err(ApiError::bad_request(
            "invalid_agent_token",
            "subagent_token's parent_agent does not name the signing agent",
        ));
    }
    if claims.iss != signer.claims.iss {
        return Err(ApiError::bad_request(
            "invalid_agent_token",
            "subagent_token was issued by a different Agent Provider than the signing agent's",
        ));
    }
    Ok(claims)
}

/// `POST /person` — issue a person token for `resource`.
pub async fn person_token(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let signer = reqctx::verify_agent_request(ctx, app, true).await?;
    let body = ctx.parse_json()?;
    let resource = body
        .get("resource")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("invalid_request", "resource is required"))?
        .to_string();
    aauth_core::ident::validate_server_identifier(&resource, app.cfg.insecure_dev_mode).map_err(
        |_| {
            ApiError::bad_request(
                "invalid_request",
                "resource is not a valid server identifier (https://host, lowercase, no \
                 port/path)",
            )
        },
    )?;
    let mission_s256: Option<String> = match body.get("mission_s256") {
        None => None,
        Some(_) if !app.cfg.missions.enabled => {
            // No mission_endpoint is advertised, so there are no missions to
            // probe and this is simply an unsupported parameter — silently
            // ignoring a parameter that changes what the token means would be
            // worse than refusing.
            return Err(ApiError::bad_request(
                "invalid_request",
                "mission_s256: this person server does not support missions (no mission_endpoint \
                 is advertised)",
            ));
        }
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| {
                    ApiError::bad_request("invalid_request", "mission_s256 must be a string")
                })?
                .to_string(),
        ),
    };
    // Call chaining: a resource acting as an agent downstream brings the auth
    // token it received upstream; we issue for the person that token was
    // issued for. The intermediary is never bound to anyone.
    let upstream = match body.get("upstream_token").and_then(|v| v.as_str()) {
        Some(tok) => Some(crate::upstream::verify(app, tok, &signer).await?),
        None => None,
    };
    if upstream.is_some() && mission_s256.is_some() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "a chained request takes its mission from the upstream token; do not also send \
             mission_s256",
        ));
    }
    let display = attested_display(&body)?;
    let (agent_iss, agent_sub) = signer.agent();
    let agent_iss = agent_iss.to_string();
    let agent_sub = agent_sub.to_string();

    // Parent-mediated: the token binds to the sub-agent's key; the person,
    // binding and consent are the parent's.
    let (cnf_jwk, subagent_sub): (Jwk, Option<String>) =
        match body.get("subagent_token").and_then(|v| v.as_str()) {
            Some(tok) => {
                let claims = verify_subagent_token(app, tok, &signer).await?;
                (claims.cnf.jwk.clone(), Some(claims.sub))
            }
            None => (signer.signing_jwk.clone(), None),
        };

    // The mission, if one is named: must exist, be active, and be this
    // agent's (unknown and not-owned are one answer, in constant time). A
    // chained request inherits the upstream token's mission, which belongs to
    // the original agent: it must simply be active.
    let mut mission_s256 = mission_s256;
    let mission_expires_at = match (&upstream, &mission_s256) {
        (Some(u), _) => match &u.mission_s256 {
            Some(s) => {
                let m = app
                    .store
                    .mission(s)?
                    .filter(|m| m.is_active())
                    .ok_or_else(|| super::mission::terminated(None))?;
                mission_s256 = Some(s.clone());
                m.expires_at
            }
            None => None,
        },
        (None, Some(s)) => super::mission::require_active_for(app, s, &signer)?.expires_at,
        (None, None) => None,
    };
    let mission_description = match &mission_s256 {
        Some(s) => app.store.mission(s)?.and_then(|m| {
            m.blob_json()
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from)
        }),
        None => None,
    };

    // Whose agent is this? Chained: the upstream token's person, no binding.
    let binding = if upstream.is_some() {
        None
    } else {
        app.store.binding(&agent_iss, &agent_sub)?
    };
    let bound_person = match &upstream {
        Some(u) => Some(u.person_id.clone()),
        None => binding
            .as_ref()
            .filter(|b| b.is_active())
            .map(|b| b.person_id.clone()),
    };

    // Distinct-resource rate limit: each new resource obliges us to derive and
    // retain a directed `sub`, which is the cost being bounded — so a resource
    // the agent already holds a token for is never blocked.
    if !app
        .store
        .agent_has_token_for(&agent_iss, &agent_sub, &resource)?
    {
        let since = aauth_core::now_unix().saturating_sub(86_400);
        let n = app
            .store
            .distinct_audiences_since(&agent_iss, &agent_sub, since)?;
        if n >= u64::from(app.cfg.limits.resources_per_agent_per_day) {
            app.record(
                bound_person.as_deref(),
                &format!("agent:{agent_sub}"),
                "person_token_denied",
                Some(&resource),
                serde_json::json!({ "agent_iss": agent_iss, "reason": "too_many_resources" }),
            );
            let mut err = ApiError::too_many_requests(
                "too_many_requests",
                format!(
                    "this agent has requested person tokens for {n} distinct resources in the \
                     last day (limit {}); try again later",
                    app.cfg.limits.resources_per_agent_per_day
                ),
            );
            err.headers.push(("retry-after", "3600".into()));
            return Err(err);
        }
    }

    // Consent on record → issue directly.
    if let Some(person_id) = &bound_person {
        if app
            .store
            .find_consent(person_id, &agent_iss, &agent_sub, &resource, "person")?
            .is_some()
        {
            let issued = issue::person_token(
                app,
                &PersonTokenRequest {
                    person_id,
                    agent_iss: &agent_iss,
                    agent_sub: &agent_sub,
                    cnf_jwk: &cnf_jwk,
                    audience: &resource,
                    agent_token_exp: signer.claims.exp,
                    mission_expires_at,
                    mission_s256: mission_s256.as_deref(),
                    tenant: upstream.as_ref().and_then(|u| u.tenant.as_deref()),
                },
            )?;
            app.record(
                Some(person_id),
                &format!("agent:{agent_sub}"),
                "person_token_issued",
                Some(&resource),
                serde_json::json!({
                    "agent_iss": agent_iss, "jti": issued.jti, "exp": issued.exp,
                    "subagent": subagent_sub, "via": "consent_on_record",
                    "mission_s256": mission_s256,
                }),
            );
            return Ok(json_ok(&serde_json::json!({
                "person_token": issued.token,
                "expires_in": issued.expires_in(),
            })));
        }
    }

    // Otherwise the person must decide. Gather what the consent screen shows
    // now, so the record of what they saw is the record of what they decided.
    let ap_meta = app
        .jwks_cache
        .get_metadata(&agent_iss, "aauth-agent.json")
        .await
        .unwrap_or(serde_json::Value::Null);
    let resource_meta = app
        .jwks_cache
        .get_metadata(&resource, "aauth-resource.json")
        .await
        .ok();
    let (code, code_hash) = pending::new_code();
    let payload = serde_json::json!({
        "resource": resource,
        "cnf_jwk": cnf_jwk.public_only(),
        "subagent_sub": subagent_sub,
        "agent_token_exp": signer.claims.exp,
        "agent_ps": signer.claims.ps,
        "platform": display.platform,
        "device": display.device,
        "ap_name": ap_meta.get("name").and_then(|v| v.as_str()),
        "ap_logo_uri": https_only(ap_meta.get("logo_uri").and_then(|v| v.as_str())),
        "resource_meta": resource_meta.as_ref().map(|m| serde_json::json!({
            "name": m.get("name").and_then(|v| v.as_str()),
            "description": m.get("description").and_then(|v| v.as_str()),
            "access_mode": m.get("access_mode").and_then(|v| v.as_str()).unwrap_or("agent-token"),
            "logo_uri": https_only(m.get("logo_uri").and_then(|v| v.as_str())),
            "documentation_uri": https_only(m.get("documentation_uri").and_then(|v| v.as_str())),
            "policy_uri": https_only(m.get("policy_uri").and_then(|v| v.as_str())),
        })),
        "code": code,
        "new_agent": binding.is_none() && upstream.is_none(),
        "mission_s256": mission_s256,
        "mission_expires_at": mission_expires_at,
        "mission_description": mission_description,
        "chained": upstream.as_ref().map(|u| serde_json::json!({
            "upstream_iss": u.iss, "upstream_jti": u.jti, "upstream_sub": u.sub,
            "upstream_aud": u.aud, "upstream_scope": u.scope, "upstream_tenant": u.tenant,
        })),
    });
    let pr = app.store.create_pending(
        "person",
        &agent_iss,
        &agent_sub,
        bound_person.as_deref(),
        &payload,
        &code_hash,
        app.cfg.limits.pending_ttl_secs,
    )?;
    app.record(
        bound_person.as_deref(),
        &format!("agent:{agent_sub}"),
        "person_token_pending",
        Some(&resource),
        serde_json::json!({ "agent_iss": agent_iss, "pending_id": pr.id, "new_agent": binding.is_none() }),
    );
    crate::notify::pending_created(app, &pr).await;

    // An agent willing to wait may get its answer on this connection.
    if let Some(d) = pending::prefer_wait(ctx.header("prefer")) {
        wait_for_decision(app, &pr.id, d).await;
    }
    poll_response(app, &pr.id, &signer).await
}

/// Hold the connection until a decision (in-process wake, or another process
/// such as the operator CLI seen by polling the row) or the deadline.
pub(super) async fn wait_for_decision(app: &Arc<App>, id: &str, d: std::time::Duration) {
    let decided_elsewhere = || {
        app.store
            .pending(id)
            .ok()
            .flatten()
            .map(|p| !p.is_open())
            .unwrap_or(true)
    };
    app.pending_notify.wait(id, d, decided_elsewhere).await;
}

fn https_only(u: Option<&str>) -> Option<&str> {
    u.filter(|u| u.starts_with("https://"))
}

/// `GET /pending/{id}` — poll a deferred request. Signed, and bound to the
/// agent that created it; anyone else sees `404`. A leaked pending URL must
/// not hand out a token: even though `cnf` makes it unusable by another key,
/// it would disclose the person's directed `sub` at that resource.
pub async fn poll(ctx: &ReqCtx, app: &Arc<App>, id: &str) -> Result<Resp, ApiError> {
    let signer = reqctx::verify_agent_request(ctx, app, false).await?;
    let pr = app.store.pending(id)?;
    let (a_iss, a_sub) = signer.agent();
    let owned = pr
        .as_ref()
        .map(|p| p.agent_iss == a_iss && p.agent_sub == a_sub)
        .unwrap_or(false);
    if !owned {
        return Err(ApiError::not_found("not_found", "no such pending request"));
    }
    if pr.as_ref().map(|p| p.is_open()).unwrap_or(false) {
        if let Some(d) = pending::prefer_wait(ctx.header("prefer")) {
            wait_for_decision(app, id, d).await;
        }
    }
    poll_response(app, id, &signer).await
}

/// The terminal or pending answer for a request the caller owns.
pub(super) async fn poll_response(
    app: &Arc<App>,
    id: &str,
    signer: &AgentSigner,
) -> Result<Resp, ApiError> {
    let pr = app
        .store
        .pending(id)?
        .ok_or_else(|| ApiError::not_found("not_found", "no such pending request"))?;
    let (_, a_sub) = signer.agent();
    match pr.state.as_str() {
        "pending" => {
            let code = pr
                .payload
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let url = format!("{}/consent", app.cfg.issuer);
            Ok(pending::accepted(
                &app.cfg.issuer,
                &pr.id,
                "pending",
                Some((&url, code)),
            ))
        }
        // The person has arrived: the agent should stop prompting.
        "interacting" => Ok(pending::accepted(
            &app.cfg.issuer,
            &pr.id,
            "interacting",
            None,
        )),
        "approved" => {
            let result = pr.result.clone().unwrap_or(serde_json::Value::Null);
            // Four-party: consent is given; the Access Server still has to
            // answer. Each poll from the agent drives one step with the AS.
            if let Some(fed) = result.get("federation").filter(|f| !f.is_null()) {
                return federation_step(app, &pr, fed, signer).await;
            }
            // Mission decisions carry a whole response object; token decisions
            // carry one token plus its `exp`.
            let body = match pr.kind.as_str() {
                "mission" | "mission_completion" => result
                    .get("response")
                    .cloned()
                    .ok_or_else(|| ApiError::server_error("approved request has no response"))?,
                kind => {
                    let field = if kind == "auth" {
                        "auth_token"
                    } else {
                        "person_token"
                    };
                    let token = result
                        .get(field)
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ApiError::server_error("approved request has no token"))?;
                    let exp = result.get("exp").and_then(|v| v.as_u64()).unwrap_or(0);
                    serde_json::json!({
                        field: token,
                        "expires_in": exp.saturating_sub(aauth_core::now_unix()),
                    })
                }
            };
            // Single delivery: a second poll of a delivered request is 410.
            if !app.store.mark_delivered(&pr.id)? {
                return Err(ApiError::new(StatusCode::GONE, "gone", "already delivered"));
            }
            app.record(
                pr.person_id.as_deref(),
                &format!("agent:{a_sub}"),
                &format!("{}_delivered", pr.kind),
                pr.payload.get("resource").and_then(|v| v.as_str()),
                serde_json::json!({ "pending_id": pr.id }),
            );
            Ok(json_ok(&body))
        }
        "delivered" => Err(ApiError::new(
            StatusCode::GONE,
            "gone",
            "this pending request was already delivered; do not retry",
        )),
        "denied" => Err(ApiError::forbidden(
            "denied",
            "the person declined the request",
        )),
        "expired" => Err(ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            "expired",
            "the person did not decide in time; you MAY start a fresh request",
        )),
        other => Err(ApiError::server_error(format!(
            "pending request in unexpected state {other}"
        ))),
    }
}

/// After a federation turn: deliver a verified AS token (recording it as
/// provided) or hand the AS's deferral to the agent through a pending row.
async fn federated_outcome(
    app: &Arc<App>,
    outcome: crate::federation::Outcome,
    expect: &crate::federation::Expect,
    person_id: &str,
    agent_iss: &str,
    agent_sub: &str,
    existing_pending: Option<&str>,
) -> Result<Resp, ApiError> {
    match outcome {
        crate::federation::Outcome::Token { token, jti, exp } => {
            app.store
                .record_auth_token(&crate::store::AuthTokenRecord {
                    jti: jti.clone(),
                    iss: Some(expect.as_iss.clone()),
                    person_id: person_id.to_string(),
                    agent_iss: agent_iss.to_string(),
                    agent_sub: agent_sub.to_string(),
                    aud: expect.resource.clone(),
                    sub: expect.sub.clone(),
                    scope: expect.requested_scope.clone(),
                    mission_s256: None,
                    iat: aauth_core::now_unix(),
                    exp,
                    revoked_at: None,
                })?;
            if let Some(id) = existing_pending {
                let _ = app.store.mark_delivered(id);
            }
            app.record(
                Some(person_id),
                &format!("agent:{agent_sub}"),
                "auth_token_provided",
                Some(&expect.resource),
                serde_json::json!({ "agent_iss": agent_iss, "access_server": expect.as_iss, "jti": jti, "exp": exp }),
            );
            Ok(json_ok(&serde_json::json!({
                "auth_token": token,
                "expires_in": exp.saturating_sub(aauth_core::now_unix()),
            })))
        }
        crate::federation::Outcome::Deferred {
            location,
            requirement,
            body,
        } => {
            let state = serde_json::json!({
                "as_location": location, "requirement": requirement, "body": body, "expect": expect,
            });
            let id = match existing_pending {
                Some(id) => {
                    // Refresh the stored federation state on the same row.
                    app.store
                        .update_pending_result(id, &serde_json::json!({ "federation": state }))?;
                    id.to_string()
                }
                None => {
                    let pr = app.store.create_pending(
                        "auth",
                        agent_iss,
                        agent_sub,
                        Some(person_id),
                        &serde_json::json!({ "resource": expect.resource, "federation": state }),
                        &pending::new_code().1,
                        app.cfg.limits.pending_ttl_secs,
                    )?;
                    app.store.decide_pending(
                        &pr.id,
                        "approved",
                        Some(&serde_json::json!({ "federation": state })),
                    )?;
                    pr.id
                }
            };
            let mut b = body;
            if b.get("status").is_none() {
                b["status"] = "pending".into();
            }
            Ok(pending::accepted_raw(
                &app.cfg.issuer,
                &id,
                requirement.as_deref(),
                b,
            ))
        }
    }
}

/// One poll step of a federated request: poll the AS's pending URL and map.
async fn federation_step(
    app: &Arc<App>,
    pr: &crate::store::Pending,
    fed: &serde_json::Value,
    signer: &AgentSigner,
) -> Result<Resp, ApiError> {
    let expect: crate::federation::Expect = serde_json::from_value(
        fed.get("expect")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|_| ApiError::server_error("federation state has no expectations"))?;
    let (a_iss, a_sub) = signer.agent();
    let person = pr.person_id.clone().unwrap_or_default();
    let outcome = match fed.get("as_location").and_then(|v| v.as_str()) {
        // Consent came first; the AS has not been called yet.
        None => {
            crate::federation::start(
                app,
                &crate::federation::FederationRequest {
                    resource_token: fed
                        .get("resource_token")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    agent_token: fed
                        .get("agent_token")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    subagent_token: fed.get("subagent_token").and_then(|v| v.as_str()),
                    upstream_token: fed.get("upstream_token").and_then(|v| v.as_str()),
                },
                &expect,
            )
            .await
        }
        Some(location) => crate::federation::poll(app, location, &expect, Some(20)).await,
    };
    match outcome {
        Ok(o) => federated_outcome(app, o, &expect, &person, a_iss, a_sub, Some(&pr.id)).await,
        Err(e) => {
            // Terminal from the AS: this pending row is spent. Say so on the
            // dashboard — the person consented and would otherwise assume the
            // access works.
            let _ = app.store.mark_delivered(&pr.id);
            record_as_refusal(app, &person, a_sub, &expect, &e);
            Err(e)
        }
    }
}

/// The Access Server refused after the person consented: make that visible.
fn record_as_refusal(
    app: &Arc<App>,
    person_id: &str,
    agent_sub: &str,
    expect: &crate::federation::Expect,
    e: &ApiError,
) {
    app.record(
        Some(person_id),
        &format!("agent:{agent_sub}"),
        "auth_token_denied",
        Some(&expect.resource),
        serde_json::json!({
            "reason": "access_server", "access_server": expect.as_iss,
            "status": e.status.as_u16(), "error": e.error, "detail": e.detail,
        }),
    );
}

/// `POST /token` — exchange a resource token for an auth token (three-party,
/// §PS Token Endpoint). The resource token names the person (`presented_jti`
/// → our retained record) and the requested `scope`; consent on record for
/// every requested scope answers `200`, otherwise the person decides.
pub async fn auth_token(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let signer = reqctx::verify_agent_request(ctx, app, true).await?;
    let body = ctx.parse_json()?;
    let resource_token = body
        .get("resource_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("invalid_request", "resource_token is required"))?
        .to_string();
    let upstream_raw = body
        .get("upstream_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let display = attested_display(&body)?;
    let justification = match body.get("justification") {
        None => None,
        Some(v) => {
            let s = v.as_str().ok_or_else(|| {
                ApiError::bad_request("invalid_request", "justification must be a string")
            })?;
            if s.len() > crate::markdown::MAX_INPUT {
                return Err(ApiError::bad_request(
                    "invalid_request",
                    format!("justification exceeds {} bytes", crate::markdown::MAX_INPUT),
                ));
            }
            Some(s.to_string())
        }
    };
    let prompt: Vec<String> = match body.get("prompt") {
        None => Vec::new(),
        Some(v) => {
            let s = v.as_str().ok_or_else(|| {
                ApiError::bad_request("invalid_request", "prompt must be a string")
            })?;
            let vals: Vec<String> = s.split_whitespace().map(|x| x.to_string()).collect();
            for x in &vals {
                if !matches!(x.as_str(), "none" | "login" | "consent" | "select_account") {
                    return Err(ApiError::bad_request(
                        "invalid_request",
                        format!(
                            "prompt value '{x}' is not one of none, login, consent, select_account"
                        ),
                    ));
                }
            }
            if vals.iter().any(|x| x == "none") && vals.len() > 1 {
                return Err(ApiError::bad_request(
                    "invalid_request",
                    "prompt=none cannot be combined with other values",
                ));
            }
            vals
        }
    };
    let capabilities: Vec<String> = body
        .get("capabilities")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let (agent_iss, agent_sub) = signer.agent();
    let agent_iss = agent_iss.to_string();
    let agent_sub = agent_sub.to_string();

    let (cnf_jwk, subagent_sub): (Jwk, Option<String>) =
        match body.get("subagent_token").and_then(|v| v.as_str()) {
            Some(tok) => {
                let claims = verify_subagent_token(app, tok, &signer).await?;
                (claims.cnf.jwk.clone(), Some(claims.sub))
            }
            None => (signer.signing_jwk.clone(), None),
        };
    let vrt = crate::restoken::verify(
        app,
        &resource_token,
        &signer,
        subagent_sub.as_ref().map(|_| &cnf_jwk),
    )
    .await?;
    let person_id = vrt.record.person_id.clone();
    // Call chaining: the upstream token names the person; it must be the same
    // person the retained record names.
    let upstream = match &upstream_raw {
        Some(tok) => {
            let u = crate::upstream::verify(app, tok, &signer).await?;
            if u.person_id != person_id {
                return Err(ApiError::bad_request(
                    "invalid_request",
                    "upstream_token was issued for a different person than the person token the \
                     resource token names",
                ));
            }
            Some(u)
        }
        None => None,
    };
    // Step 7: a mission named by the resource token must be active and not
    // past its `expires_at`; every token issued under it is capped by it. A
    // chained request's mission belongs to the original agent — active only.
    let mission_expires_at = match (&vrt.mission_s256, &upstream) {
        (Some(s), Some(_)) => {
            app.store
                .mission(s)?
                .filter(|m| m.is_active())
                .ok_or_else(|| super::mission::terminated(None))?
                .expires_at
        }
        (Some(s), None) => super::mission::require_active_for(app, s, &signer)?.expires_at,
        (None, _) => None,
    };

    // The person may have revoked the agent since the person token was
    // issued. (A chained intermediary has no binding by design.)
    if upstream.is_none() {
        match app.store.binding(&agent_iss, &agent_sub)? {
            Some(b) if b.is_active() && b.person_id == person_id => {}
            _ => {
                app.record(
                    Some(&person_id),
                    &format!("agent:{agent_sub}"),
                    "auth_token_denied",
                    Some(&vrt.resource),
                    serde_json::json!({ "agent_iss": agent_iss, "reason": "binding_revoked" }),
                );
                return Err(ApiError::forbidden(
                    "denied",
                    "the person has revoked this agent",
                ));
            }
        }
    }
    // Four-party: what the Access Server's token must say.
    let expect = vrt
        .access_server
        .as_ref()
        .map(|as_iss| crate::federation::Expect {
            as_iss: as_iss.clone(),
            resource: vrt.resource.clone(),
            cnf_jwk: cnf_jwk.public_only(),
            sub: vrt.sub.clone(),
            requested_scope: vrt.scope.clone(),
        });

    let requested: std::collections::BTreeSet<String> = vrt
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(String::from)
        .collect();
    let granted = app
        .store
        .granted_scopes(&person_id, &agent_iss, &agent_sub, &vrt.resource)?;
    let covered = requested.is_subset(&granted);
    let force_consent = prompt.iter().any(|p| p == "consent");

    if covered && !force_consent {
        if let Some(expect) = &expect {
            // Consent on record: straight to the Access Server.
            let outcome = match crate::federation::start(
                app,
                &crate::federation::FederationRequest {
                    resource_token: &resource_token,
                    agent_token: &signer.token,
                    subagent_token: body.get("subagent_token").and_then(|v| v.as_str()),
                    upstream_token: upstream_raw.as_deref(),
                },
                expect,
            )
            .await
            {
                Ok(o) => o,
                Err(e) => {
                    record_as_refusal(app, &person_id, &agent_sub, expect, &e);
                    return Err(e);
                }
            };
            return federated_outcome(
                app, outcome, expect, &person_id, &agent_iss, &agent_sub, None,
            )
            .await;
        }
        let issued = issue::auth_token(
            app,
            &issue::AuthTokenRequest {
                person_id: &person_id,
                agent_iss: &agent_iss,
                agent_sub: &agent_sub,
                cnf_jwk: &cnf_jwk,
                audience: &vrt.resource,
                sub: &vrt.sub,
                scope: vrt.scope.as_deref(),
                account: vrt.account.as_deref(),
                mission_s256: vrt.mission_s256.as_deref(),
                tenant: vrt.tenant.as_deref(),
                agent_token_exp: signer.claims.exp,
                mission_expires_at,
            },
        )?;
        app.record(
            Some(&person_id),
            &format!("agent:{agent_sub}"),
            "auth_token_issued",
            Some(&vrt.resource),
            serde_json::json!({
                "agent_iss": agent_iss, "jti": issued.jti, "exp": issued.exp, "scope": vrt.scope,
                "resource_jti": vrt.jti, "presented_jti": vrt.presented_jti,
                "subagent": subagent_sub, "via": "consent_on_record",
                "justification": justification,
            }),
        );
        return Ok(json_ok(&serde_json::json!({
            "auth_token": issued.token,
            "expires_in": issued.expires_in(),
        })));
    }
    if prompt.iter().any(|p| p == "none") {
        // Not `denied`: the person was never asked. `prompt=none` is the agent
        // declining the only channel there is, which is what
        // `user_unreachable` describes.
        return Err(ApiError::forbidden(
            "user_unreachable",
            "consent is required for the requested scope and prompt=none forbids asking the \
             person; retry without prompt=none",
        ));
    }

    // The person decides. Gather what the screen shows now.
    let ap_meta = app
        .jwks_cache
        .get_metadata(&agent_iss, "aauth-agent.json")
        .await
        .unwrap_or(serde_json::Value::Null);
    let resource_meta = app
        .jwks_cache
        .get_metadata(&vrt.resource, "aauth-resource.json")
        .await
        .ok();
    let (code, code_hash) = pending::new_code();
    let payload = serde_json::json!({
        "resource": vrt.resource,
        "resource_token": {
            "jti": vrt.jti, "sub": vrt.sub, "scope": vrt.scope, "account": vrt.account,
            "presented_jti": vrt.presented_jti, "exp": vrt.exp, "tenant": vrt.tenant,
            "mission_s256": vrt.mission_s256,
        },
        "requested_scopes": requested.iter().cloned().collect::<Vec<_>>(),
        "cnf_jwk": cnf_jwk.public_only(),
        "subagent_sub": subagent_sub,
        "agent_token_exp": signer.claims.exp,
        "agent_ps": signer.claims.ps,
        "platform": display.platform,
        "device": display.device,
        "ap_name": ap_meta.get("name").and_then(|v| v.as_str()),
        "ap_logo_uri": https_only(ap_meta.get("logo_uri").and_then(|v| v.as_str())),
        "resource_meta": resource_meta.as_ref().map(|m| serde_json::json!({
            "name": m.get("name").and_then(|v| v.as_str()),
            "description": m.get("description").and_then(|v| v.as_str()),
            "access_mode": m.get("access_mode").and_then(|v| v.as_str()).unwrap_or("agent-token"),
            "logo_uri": https_only(m.get("logo_uri").and_then(|v| v.as_str())),
            "scope_descriptions": m.get("scope_descriptions").cloned().unwrap_or(serde_json::Value::Null),
        })),
        "justification": justification,
        "capabilities": capabilities,
        "prompt": prompt,
        "mission_s256": vrt.mission_s256,
        "mission_expires_at": mission_expires_at,
        "hints": {
            "login_hint": body.get("login_hint"), "tenant": body.get("tenant"),
            "domain_hint": body.get("domain_hint"),
        },
        "code": code,
        "new_agent": false,
        "chained": upstream.as_ref().map(|u| serde_json::json!({
            "upstream_iss": u.iss, "upstream_jti": u.jti, "upstream_sub": u.sub,
            "upstream_aud": u.aud, "upstream_scope": u.scope, "upstream_tenant": u.tenant,
        })),
        "federation": expect.as_ref().map(|e| serde_json::json!({
            "expect": e,
            "resource_token": resource_token,
            "agent_token": signer.token,
            "subagent_token": body.get("subagent_token"),
            "upstream_token": upstream_raw,
        })),
    });
    let pr = app.store.create_pending(
        "auth",
        &agent_iss,
        &agent_sub,
        Some(&person_id),
        &payload,
        &code_hash,
        app.cfg.limits.pending_ttl_secs,
    )?;
    app.record(
        Some(&person_id),
        &format!("agent:{agent_sub}"),
        "auth_token_pending",
        Some(&vrt.resource),
        serde_json::json!({ "agent_iss": agent_iss, "pending_id": pr.id, "scope": vrt.scope }),
    );
    crate::notify::pending_created(app, &pr).await;
    if let Some(d) = pending::prefer_wait(ctx.header("prefer")) {
        wait_for_decision(app, &pr.id, d).await;
    }
    poll_response(app, &pr.id, &signer).await
}
