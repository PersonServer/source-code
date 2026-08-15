//! The mission endpoint — the owning agent's surface (§Mission): three
//! operations of one shape. The agent proposes, the person decides, the
//! response is deferred.
//!
//! - `POST /mission` — propose (`description`, optional `tools`, `resources`)
//! - `POST /mission/{s256}` with `action: update` — record a change; appended
//!   to the log and digested; changes nothing about the blob or any token
//! - `POST /mission/{s256}` with `action: completion` — propose that the
//!   mission is finished; only the person's acceptance terminates it
//!
//! `{s256}` errors (§Mission Endpoint Errors): a mission that does not exist
//! and one that exists but is not this agent's MUST be indistinguishable —
//! same status, error, body, headers, **and timing**. `mission_s256` values
//! travel in auth tokens to resources, so a resource operator running an
//! agent could otherwise probe whether a mission it once saw is still live.
//! The natural arrangement — look the row up, then check ownership only when
//! it exists — leaks exactly that difference in timing, which is why
//! [`lookup_owned`] always runs the same query and the same constant-time
//! comparison whether or not a row came back. Anyone "simplifying" it will
//! reintroduce the oracle.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::app::App;
use crate::pending;
use crate::problem::{json_ok, ApiError, Resp};
use crate::reqctx::{self, AgentSigner, ReqCtx};
use crate::store::Mission;

/// Longest proposal / update / summary text we accept.
const MAX_TEXT: usize = crate::markdown::MAX_INPUT;
/// Bounds on the optional lists.
const MAX_TOOLS: usize = 64;
const MAX_RESOURCES: usize = 32;

/// The three-way outcome of resolving `{s256}` for the authenticated agent.
pub enum Lookup {
    /// Unknown, or not this agent's — the two are one answer by design.
    NotFoundOrNotOwned,
    /// This agent's mission, permanently ended.
    Terminated {
        reason: Option<String>,
    },
    Active(Mission),
}

/// Resolve `s256` for `signer` in constant time with respect to existence
/// versus ownership: the row is fetched (or not) and the ownership digest is
/// compared with a constant-time equality either way, against a fixed dummy
/// when there is no row.
pub fn lookup_owned(app: &App, s256: &str, signer: &AgentSigner) -> Result<Lookup, ApiError> {
    let row = app.store.mission(s256)?;
    let (a_iss, a_sub) = signer.agent();
    let mine = owner_digest(a_iss, a_sub);
    let theirs = match &row {
        Some(m) => owner_digest(&m.owner_iss, &m.owner_sub),
        None => owner_digest("\u{0}no-such-mission", "\u{0}"),
    };
    // Constant-time: no early exit on the first differing byte.
    let owned: bool = mine.ct_eq(&theirs).into();
    let exists = row.is_some();
    // Combine without branching on the individual bits.
    if !(exists & owned) {
        return Ok(Lookup::NotFoundOrNotOwned);
    }
    let m = row.expect("exists");
    if !m.is_active() {
        return Ok(Lookup::Terminated {
            reason: m.termination_reason.clone(),
        });
    }
    Ok(Lookup::Active(m))
}

fn owner_digest(iss: &str, sub: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(iss.as_bytes());
    h.update([0u8]);
    h.update(sub.as_bytes());
    h.finalize().into()
}

/// The one `404` for unknown-or-not-owned. Built the same way on both paths.
pub fn not_found() -> ApiError {
    ApiError::not_found("mission_not_found", "no such mission")
}

pub fn terminated(reason: Option<String>) -> ApiError {
    let mut e = ApiError::forbidden(
        "mission_terminated",
        "the mission is permanently ended; stop acting on it",
    )
    .with_member("mission_status", "terminated".into());
    if let Some(r) = reason {
        e = e.with_member("termination_reason", r.into());
    }
    e
}

/// A well-formed `mission_s256`: unpadded base64url of 32 bytes.
pub fn valid_s256(s: &str) -> bool {
    s.len() == 43
        && aauth_core::b64::decode(s)
            .map(|b| b.len() == 32)
            .unwrap_or(false)
}

fn text_field(
    body: &serde_json::Value,
    name: &str,
    required: bool,
) -> Result<Option<String>, ApiError> {
    match body.get(name) {
        None if required => Err(ApiError::bad_request(
            "invalid_request",
            format!("{name} is required"),
        )),
        None => Ok(None),
        Some(v) => {
            let s = v.as_str().ok_or_else(|| {
                ApiError::bad_request("invalid_request", format!("{name} must be a string"))
            })?;
            if s.trim().is_empty() {
                return Err(ApiError::bad_request(
                    "invalid_request",
                    format!("{name} must not be empty"),
                ));
            }
            if s.len() > MAX_TEXT {
                return Err(ApiError::bad_request(
                    "invalid_request",
                    format!("{name} exceeds {MAX_TEXT} bytes"),
                ));
            }
            Ok(Some(s.to_string()))
        }
    }
}

fn require_missions(app: &App) -> Result<(), ApiError> {
    if app.cfg.missions.enabled {
        Ok(())
    } else {
        Err(ApiError::not_found(
            "not_found",
            "this person server does not support missions",
        ))
    }
}

/// `POST /mission` — propose a mission.
pub async fn propose(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    require_missions(app)?;
    let signer = reqctx::verify_agent_request(ctx, app, true).await?;
    let body = ctx.parse_json()?;
    let description = text_field(&body, "description", true)?.expect("required");
    let mut tools: Vec<serde_json::Value> = Vec::new();
    if let Some(t) = body.get("tools") {
        let arr = t
            .as_array()
            .ok_or_else(|| ApiError::bad_request("invalid_request", "tools must be an array"))?;
        if arr.len() > MAX_TOOLS {
            return Err(ApiError::bad_request(
                "invalid_request",
                format!("at most {MAX_TOOLS} tools"),
            ));
        }
        for tool in arr {
            let name = tool.get("name").and_then(|v| v.as_str());
            let desc = tool.get("description").and_then(|v| v.as_str());
            match (name, desc) {
                (Some(n), Some(d)) if !n.is_empty() && n.len() <= 128 && d.len() <= 1024 => {
                    tools.push(serde_json::json!({ "name": n, "description": d }));
                }
                _ => {
                    return Err(ApiError::bad_request(
                        "invalid_request",
                        "each tool needs a name (≤128) and a description (≤1024)",
                    ))
                }
            }
        }
    }
    let mut resources: Vec<String> = Vec::new();
    if let Some(r) = body.get("resources") {
        let arr = r.as_array().ok_or_else(|| {
            ApiError::bad_request("invalid_request", "resources must be an array")
        })?;
        if arr.len() > MAX_RESOURCES {
            return Err(ApiError::bad_request(
                "invalid_request",
                format!("at most {MAX_RESOURCES} resources"),
            ));
        }
        for v in arr {
            let s = v.as_str().ok_or_else(|| {
                ApiError::bad_request("invalid_request", "resources must be strings")
            })?;
            aauth_core::ident::validate_server_identifier(s, app.cfg.insecure_dev_mode).map_err(
                |_| {
                    ApiError::bad_request(
                        "invalid_request",
                        format!("resource '{s}' is not a valid server identifier"),
                    )
                },
            )?;
            if !resources.iter().any(|x| x == s) {
                resources.push(s.to_string());
            }
        }
    }
    let (agent_iss, agent_sub) = signer.agent();
    let (agent_iss, agent_sub) = (agent_iss.to_string(), agent_sub.to_string());
    let binding = app.store.binding(&agent_iss, &agent_sub)?;
    let bound_person = binding
        .as_ref()
        .filter(|b| b.is_active())
        .map(|b| b.person_id.clone());

    // What the consent screen shows: fetch each named resource's metadata now
    // (bounded list, egress admission), so the record of what was shown is
    // the record of what was approved.
    let ap_meta = app
        .jwks_cache
        .get_metadata(&agent_iss, "aauth-agent.json")
        .await
        .unwrap_or(serde_json::Value::Null);
    let mut resource_metas = Vec::new();
    for r in &resources {
        let m = app
            .jwks_cache
            .get_metadata(r, "aauth-resource.json")
            .await
            .ok();
        resource_metas.push(serde_json::json!({
            "resource": r,
            "name": m.as_ref().and_then(|m| m.get("name")).and_then(|v| v.as_str()),
            "description": m.as_ref().and_then(|m| m.get("description")).and_then(|v| v.as_str()),
            "access_mode": m.as_ref().and_then(|m| m.get("access_mode")).and_then(|v| v.as_str()).unwrap_or("agent-token"),
        }));
    }
    let (code, code_hash) = pending::new_code();
    let payload = serde_json::json!({
        "description": description,
        "tools": tools,
        "resources": resources,
        "resource_metas": resource_metas,
        "cnf_jwk": signer.signing_jwk.public_only(),
        "agent_token_exp": signer.claims.exp,
        "agent_ps": signer.claims.ps,
        "ap_name": ap_meta.get("name").and_then(|v| v.as_str()),
        "ap_logo_uri": ap_meta.get("logo_uri").and_then(|v| v.as_str()).filter(|u| u.starts_with("https://")),
        "code": code,
        "new_agent": binding.is_none(),
    });
    let pr = app.store.create_pending(
        "mission",
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
        "mission_proposed",
        None,
        serde_json::json!({ "agent_iss": agent_iss, "pending_id": pr.id, "resources": resources }),
    );
    crate::notify::pending_created(app, &pr).await;
    if let Some(d) = pending::prefer_wait(ctx.header("prefer")) {
        super::tokens::wait_for_decision(app, &pr.id, d).await;
    }
    super::tokens::poll_response(app, &pr.id, &signer).await
}

/// `POST /mission/{s256}` — `action: update` or `action: completion`.
pub async fn act(ctx: &ReqCtx, app: &Arc<App>, s256: &str) -> Result<Resp, ApiError> {
    require_missions(app)?;
    let signer = reqctx::verify_agent_request(ctx, app, true).await?;
    // Malformed path segment and missing/unknown action are 400s that reveal
    // nothing about any mission; they are decided before the lookup.
    if !valid_s256(s256) {
        return Err(ApiError::bad_request(
            "invalid_request",
            "the mission_s256 path segment is malformed",
        ));
    }
    let body = ctx.parse_json()?;
    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("invalid_request", "action is required"))?
        .to_string();
    if action != "update" && action != "completion" {
        return Err(ApiError::bad_request(
            "invalid_request",
            format!("action '{action}' is not recognized (update, completion)"),
        ));
    }
    let text = match action.as_str() {
        "update" => text_field(&body, "description", true)?.expect("required"),
        _ => text_field(&body, "summary", true)?.expect("required"),
    };
    let mission = match lookup_owned(app, s256, &signer)? {
        Lookup::NotFoundOrNotOwned => return Err(not_found()),
        Lookup::Terminated { reason } => return Err(terminated(reason)),
        Lookup::Active(m) => m,
    };
    let (_, agent_sub) = signer.agent();
    if action == "update" {
        // Accepted as recorded: the blob and every token are unchanged; what
        // changes is the context the person will read the mission in. The
        // digest returned covers the exact bytes stored.
        let entry = app
            .store
            .append_mission_log(s256, "update", text.as_bytes())?;
        app.record(
            Some(&mission.person_id),
            &format!("agent:{agent_sub}"),
            "mission_updated",
            Some(s256),
            serde_json::json!({ "seq": entry.seq, "s256": entry.s256 }),
        );
        return Ok(json_ok(&serde_json::json!({ "s256": entry.s256 })));
    }
    // Completion: the person decides; only their acceptance terminates.
    let (code, code_hash) = pending::new_code();
    let payload = serde_json::json!({
        "mission_s256": s256,
        "summary": text,
        "cnf_jwk": signer.signing_jwk.public_only(),
        "agent_token_exp": signer.claims.exp,
        "code": code,
        "new_agent": false,
    });
    let pr = app.store.create_pending(
        "mission_completion",
        &mission.owner_iss,
        &mission.owner_sub,
        Some(&mission.person_id),
        &payload,
        &code_hash,
        app.cfg.limits.pending_ttl_secs,
    )?;
    app.store
        .append_mission_log(s256, "completion_proposed", text.as_bytes())?;
    app.record(
        Some(&mission.person_id),
        &format!("agent:{agent_sub}"),
        "mission_completion_proposed",
        Some(s256),
        serde_json::json!({ "pending_id": pr.id }),
    );
    crate::notify::pending_created(app, &pr).await;
    if let Some(d) = pending::prefer_wait(ctx.header("prefer")) {
        super::tokens::wait_for_decision(app, &pr.id, d).await;
    }
    super::tokens::poll_response(app, &pr.id, &signer).await
}

/// The mission an agent named on a `/person` (or later) request: the same
/// constant-time lookup, then the terminated / active split. Returns the
/// active mission.
pub fn require_active_for(
    app: &App,
    s256: &str,
    signer: &AgentSigner,
) -> Result<Mission, ApiError> {
    if !valid_s256(s256) {
        return Err(ApiError::bad_request(
            "invalid_request",
            "mission_s256 is malformed",
        ));
    }
    match lookup_owned(app, s256, signer)? {
        Lookup::NotFoundOrNotOwned => Err(not_found()),
        Lookup::Terminated { reason } => Err(terminated(reason)),
        Lookup::Active(m) => Ok(m),
    }
}

/// Terminate a mission on the person's or operator's behalf and revoke the
/// auth tokens issued under it (§Token Revocation: PS revokes a mission).
pub async fn terminate(
    app: &Arc<App>,
    s256: &str,
    reason: &str,
    via: &str,
) -> Result<bool, ApiError> {
    let Some(m) = app.store.mission(s256)? else {
        return Ok(false);
    };
    if !app.store.terminate_mission(s256, reason)? {
        return Ok(false);
    }
    app.record(
        Some(&m.person_id),
        via,
        "mission_terminated",
        Some(s256),
        serde_json::json!({ "reason": reason, "agent_iss": m.owner_iss, "agent_sub": m.owner_sub }),
    );
    let app2 = app.clone();
    let s = s256.to_string();
    tokio::spawn(async move {
        crate::revocation::revoke_auth_tokens_for_mission(&app2, &s, "mission_terminated").await;
    });
    Ok(true)
}
