//! The person's decision on a pending request, as one operation shared by
//! the consent screen (`handlers/ui.rs`) and the operator CLI
//! (`psd pending approve|deny`). Approval binds the agent (invariant in the
//! store), records consent, mints and retains the person token, and resolves
//! the pending request; every step is audited.

use std::sync::Arc;

use crate::app::App;
use crate::issue::{self, PersonTokenRequest};
use crate::store::{BindOutcome, BindingDisplay, Pending};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproveOutcome {
    /// Approved and the token is waiting for the agent's poll.
    Approved { jti: String, exp: u64 },
    /// The agent is actively bound to another person: request denied.
    BoundElsewhere { owner: String },
    /// The pending request expired (or the agent token did) before the
    /// decision was recorded.
    Expired,
}

/// Approve `pr` as `person_id`. `pr` must be open and claimed by (or
/// claimable for) this person — the caller checks that.
/// `via` names the channel the decision came through — `"consent"` for the
/// passkey-authenticated browser session, `"cli"` for the operator shell. A
/// shell decision and a passkey-authenticated one must stay distinguishable
/// afterwards: the audit trail is what answers "did the human actually
/// consent?", and in a multi-person deployment the operator is not the person.
pub fn approve(
    app: &Arc<App>,
    person_id: &str,
    pr: &Pending,
    via: &str,
) -> Result<ApproveOutcome, String> {
    match pr.kind.as_str() {
        "auth" => return approve_auth(app, person_id, pr, via),
        "mission" => {
            return approve_mission(
                app,
                person_id,
                pr,
                via,
                Some(app.cfg.missions.default_ttl_secs),
            )
        }
        "mission_completion" => return approve_completion(app, person_id, pr, via),
        _ => {}
    }
    let resource = pr
        .payload
        .get("resource")
        .and_then(|v| v.as_str())
        .ok_or("pending request has no resource")?
        .to_string();
    let display = BindingDisplay {
        platform: pr
            .payload
            .get("platform")
            .and_then(|v| v.as_str())
            .map(String::from),
        device: pr
            .payload
            .get("device")
            .and_then(|v| v.as_str())
            .map(String::from),
        ap_name: pr
            .payload
            .get("ap_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        ap_logo_uri: pr
            .payload
            .get("ap_logo_uri")
            .and_then(|v| v.as_str())
            .map(String::from),
    };
    // A chained request comes from a resource acting as an agent, which acts
    // for many people and is never bound to one; the person is established by
    // the upstream token instead.
    let chained = pr
        .payload
        .get("chained")
        .map(|c| !c.is_null())
        .unwrap_or(false);
    // 1. Binding — the invariant lives in the store.
    let bind = if chained {
        Ok(BindOutcome::Existing)
    } else {
        app.store
            .bind_agent(&pr.agent_iss, &pr.agent_sub, person_id, &display)
            .map_err(|e| e.to_string())?
    };
    match bind {
        Ok(outcome) => {
            if outcome != BindOutcome::Existing {
                app.record(
                    Some(person_id),
                    "person",
                    "agent_bound",
                    Some(&pr.agent_sub),
                    serde_json::json!({ "agent_iss": pr.agent_iss, "outcome": format!("{outcome:?}"), "via": via }),
                );
            }
        }
        Err(other) => {
            // Fail closed: deny the request.
            app.store
                .decide_pending(&pr.id, "denied", None)
                .map_err(|e| e.to_string())?;
            app.pending_notify.decided(&pr.id);
            app.record(
                Some(person_id),
                "person",
                "consent_refused_bound_elsewhere",
                Some(&pr.agent_sub),
                serde_json::json!({ "agent_iss": pr.agent_iss, "owner": other.owner }),
            );
            return Ok(ApproveOutcome::BoundElsewhere { owner: other.owner });
        }
    }
    // 2. Consent + token; the pending row is the outbox for the agent's poll.
    let cnf_jwk: aauth_core::jwk::Jwk = serde_json::from_value(
        pr.payload
            .get("cnf_jwk")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|_| "pending request has no usable cnf_jwk".to_string())?;
    let agent_token_exp = pr
        .payload
        .get("agent_token_exp")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    app.store
        .grant_consent(
            person_id,
            &pr.agent_iss,
            &pr.agent_sub,
            &resource,
            "person",
            None,
            None,
        )
        .map_err(|e| e.to_string())?;
    // A request made under a mission: the token carries it and is capped by
    // its expiry (recorded on the pending row when the request was verified).
    let mission_s256 = pr
        .payload
        .get("mission_s256")
        .and_then(|v| v.as_str())
        .map(String::from);
    let mission_expires_at = pr
        .payload
        .get("mission_expires_at")
        .and_then(|v| v.as_u64());
    let tenant = pr
        .payload
        .get("chained")
        .and_then(|c| c.get("upstream_tenant"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let issued = match issue::person_token(
        app,
        &PersonTokenRequest {
            person_id,
            agent_iss: &pr.agent_iss,
            agent_sub: &pr.agent_sub,
            cnf_jwk: &cnf_jwk,
            audience: &resource,
            agent_token_exp,
            mission_expires_at,
            mission_s256: mission_s256.as_deref(),
            tenant: tenant.as_deref(),
        },
    ) {
        Ok(i) => i,
        Err(e) => {
            // e.g. the agent token expired while the person was deciding.
            app.store
                .decide_pending(&pr.id, "expired", None)
                .map_err(|e| e.to_string())?;
            app.pending_notify.decided(&pr.id);
            app.record(
                Some(person_id),
                "person",
                "consent_expired",
                Some(&resource),
                serde_json::json!({ "agent_iss": pr.agent_iss, "agent_sub": pr.agent_sub, "reason": e.detail }),
            );
            return Ok(ApproveOutcome::Expired);
        }
    };
    let result = serde_json::json!({
        "person_token": issued.token, "exp": issued.exp, "jti": issued.jti, "sub": issued.sub,
    });
    if !app
        .store
        .decide_pending(&pr.id, "approved", Some(&result))
        .map_err(|e| e.to_string())?
    {
        return Ok(ApproveOutcome::Expired);
    }
    app.pending_notify.decided(&pr.id);
    app.record(
        Some(person_id),
        "person",
        "consent_granted",
        Some(&resource),
        serde_json::json!({ "agent_iss": pr.agent_iss, "agent_sub": pr.agent_sub, "kind": "person", "via": via }),
    );
    app.record(
        Some(person_id),
        &format!("agent:{}", pr.agent_sub),
        "person_token_issued",
        Some(&resource),
        serde_json::json!({
            "agent_iss": pr.agent_iss, "jti": issued.jti, "exp": issued.exp,
            "subagent": pr.payload.get("subagent_sub"), "via": via, "pending_id": pr.id,
            "mission_s256": mission_s256,
        }),
    );
    Ok(ApproveOutcome::Approved {
        jti: issued.jti,
        exp: issued.exp,
    })
}

/// Approve an `auth` request: the agent is already bound (it holds a person
/// token); the person grants the requested scope and the auth token is minted.
fn approve_auth(
    app: &Arc<App>,
    person_id: &str,
    pr: &Pending,
    via: &str,
) -> Result<ApproveOutcome, String> {
    let resource = pr
        .payload
        .get("resource")
        .and_then(|v| v.as_str())
        .ok_or("pending request has no resource")?
        .to_string();
    let chained = pr
        .payload
        .get("chained")
        .map(|c| !c.is_null())
        .unwrap_or(false);
    // The binding must still be active for this person (fail closed) — for a
    // direct agent; a chained intermediary has no binding by design.
    let binding = if chained {
        None
    } else {
        app.store
            .binding(&pr.agent_iss, &pr.agent_sub)
            .map_err(|e| e.to_string())?
    };
    match binding {
        _ if chained => {}
        Some(b) if b.is_active() && b.person_id == person_id => {}
        Some(b) if b.is_active() => {
            app.store
                .decide_pending(&pr.id, "denied", None)
                .map_err(|e| e.to_string())?;
            app.pending_notify.decided(&pr.id);
            return Ok(ApproveOutcome::BoundElsewhere { owner: b.person_id });
        }
        _ => {
            app.store
                .decide_pending(&pr.id, "denied", None)
                .map_err(|e| e.to_string())?;
            app.pending_notify.decided(&pr.id);
            app.record(
                Some(person_id),
                "person",
                "consent_refused_binding_revoked",
                Some(&pr.agent_sub),
                serde_json::json!({ "agent_iss": pr.agent_iss }),
            );
            return Ok(ApproveOutcome::Expired);
        }
    }
    let rt = pr
        .payload
        .get("resource_token")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let scopes: Vec<String> = pr
        .payload
        .get("requested_scopes")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let scope_str = if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    };
    let cnf_jwk: aauth_core::jwk::Jwk = serde_json::from_value(
        pr.payload
            .get("cnf_jwk")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|_| "pending request has no usable cnf_jwk".to_string())?;
    let agent_token_exp = pr
        .payload
        .get("agent_token_exp")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let sub = rt
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if sub.is_empty() {
        return Err("pending auth request has no sub".into());
    }
    app.store
        .grant_consent(
            person_id,
            &pr.agent_iss,
            &pr.agent_sub,
            &resource,
            "auth",
            scope_str.as_deref(),
            None,
        )
        .map_err(|e| e.to_string())?;
    // Four-party: consent obtained, now the Access Server evaluates policy.
    // The pending row is marked approved and carries the federation state;
    // the agent's polls drive the AS from there.
    if let Some(fed) = pr.payload.get("federation").filter(|f| !f.is_null()) {
        let result = serde_json::json!({ "federation": fed });
        if !app
            .store
            .decide_pending(&pr.id, "approved", Some(&result))
            .map_err(|e| e.to_string())?
        {
            return Ok(ApproveOutcome::Expired);
        }
        app.pending_notify.decided(&pr.id);
        app.record(
            Some(person_id),
            "person",
            "consent_granted",
            Some(&resource),
            serde_json::json!({ "agent_iss": pr.agent_iss, "agent_sub": pr.agent_sub, "kind": "auth",
                                "scope": scope_str, "via": via, "federated": true }),
        );
        return Ok(ApproveOutcome::Approved {
            jti: String::new(),
            exp: 0,
        });
    }
    let issued = match issue::auth_token(
        app,
        &issue::AuthTokenRequest {
            person_id,
            agent_iss: &pr.agent_iss,
            agent_sub: &pr.agent_sub,
            cnf_jwk: &cnf_jwk,
            audience: &resource,
            sub: &sub,
            scope: rt.get("scope").and_then(|v| v.as_str()),
            account: rt.get("account").and_then(|v| v.as_str()),
            mission_s256: rt.get("mission_s256").and_then(|v| v.as_str()),
            tenant: rt.get("tenant").and_then(|v| v.as_str()),
            agent_token_exp,
            // Recorded when the resource token was verified: no token issued
            // under a mission may outlive it.
            mission_expires_at: pr
                .payload
                .get("mission_expires_at")
                .and_then(|v| v.as_u64()),
        },
    ) {
        Ok(i) => i,
        Err(e) => {
            app.store
                .decide_pending(&pr.id, "expired", None)
                .map_err(|e| e.to_string())?;
            app.pending_notify.decided(&pr.id);
            app.record(
                Some(person_id),
                "person",
                "consent_expired",
                Some(&resource),
                serde_json::json!({ "agent_iss": pr.agent_iss, "agent_sub": pr.agent_sub, "reason": e.detail }),
            );
            return Ok(ApproveOutcome::Expired);
        }
    };
    let result =
        serde_json::json!({ "auth_token": issued.token, "exp": issued.exp, "jti": issued.jti });
    if !app
        .store
        .decide_pending(&pr.id, "approved", Some(&result))
        .map_err(|e| e.to_string())?
    {
        return Ok(ApproveOutcome::Expired);
    }
    app.pending_notify.decided(&pr.id);
    app.record(
        Some(person_id),
        "person",
        "consent_granted",
        Some(&resource),
        serde_json::json!({ "agent_iss": pr.agent_iss, "agent_sub": pr.agent_sub, "kind": "auth", "scope": scope_str, "via": via }),
    );
    app.record(
        Some(person_id),
        &format!("agent:{}", pr.agent_sub),
        "auth_token_issued",
        Some(&resource),
        serde_json::json!({
            "agent_iss": pr.agent_iss, "jti": issued.jti, "exp": issued.exp, "scope": scope_str,
            "resource_jti": rt.get("jti"), "presented_jti": rt.get("presented_jti"),
            "subagent": pr.payload.get("subagent_sub"), "via": via, "pending_id": pr.id,
            "justification": pr.payload.get("justification"),
        }),
    );
    Ok(ApproveOutcome::Approved {
        jti: issued.jti,
        exp: issued.exp,
    })
}

/// Approve a mission proposal. Builds the mission blob, computes `s256` over
/// the exact bytes stored, binds the agent if needed, grants consent for each
/// approved resource and issues a person token for it (capped by
/// `expires_at`), and resolves the pending request with the approval response.
/// `expires_in`: seconds until the mission expires, or `None` for no expiry.
pub fn approve_mission(
    app: &Arc<App>,
    person_id: &str,
    pr: &Pending,
    via: &str,
    expires_in: Option<u64>,
) -> Result<ApproveOutcome, String> {
    let display = BindingDisplay {
        ap_name: pr
            .payload
            .get("ap_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        ap_logo_uri: pr
            .payload
            .get("ap_logo_uri")
            .and_then(|v| v.as_str())
            .map(String::from),
        ..Default::default()
    };
    match app
        .store
        .bind_agent(&pr.agent_iss, &pr.agent_sub, person_id, &display)
        .map_err(|e| e.to_string())?
    {
        Ok(outcome) => {
            if outcome != BindOutcome::Existing {
                app.record(
                    Some(person_id),
                    "person",
                    "agent_bound",
                    Some(&pr.agent_sub),
                    serde_json::json!({ "agent_iss": pr.agent_iss, "outcome": format!("{outcome:?}"), "via": via }),
                );
            }
        }
        Err(other) => {
            app.store
                .decide_pending(&pr.id, "denied", None)
                .map_err(|e| e.to_string())?;
            app.pending_notify.decided(&pr.id);
            return Ok(ApproveOutcome::BoundElsewhere { owner: other.owner });
        }
    }
    let now = aauth_core::now_unix();
    let expires_at = expires_in.map(|s| now + s);
    let description = pr
        .payload
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let tools = pr
        .payload
        .get("tools")
        .cloned()
        .unwrap_or(serde_json::json!([]));
    let resources: Vec<String> = pr
        .payload
        .get("resources")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    // The blob. Member lists are a floor; a blob with an extra member is a
    // different mission because it has a different digest.
    let mut blob = serde_json::Map::new();
    blob.insert("approver".into(), app.cfg.issuer.clone().into());
    blob.insert("agent".into(), pr.agent_sub.clone().into());
    blob.insert("approved_at".into(), crate::ui::iso8601(now).into());
    if let Some(e) = expires_at {
        blob.insert("expires_at".into(), crate::ui::iso8601(e).into());
    }
    blob.insert("description".into(), description.into());
    if tools.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
        blob.insert("approved_tools".into(), tools);
    }
    if !resources.is_empty() {
        blob.insert("approved_resources".into(), serde_json::json!(resources));
    }
    // serde_json serializes maps with sorted keys and no whitespace: the same
    // blob always yields the same bytes.
    let bytes = serde_json::to_vec(&serde_json::Value::Object(blob)).map_err(|e| e.to_string())?;
    let s256 = {
        use sha2::Digest;
        aauth_core::b64::encode(&sha2::Sha256::digest(&bytes))
    };
    app.store
        .create_mission(&crate::store::Mission {
            s256: s256.clone(),
            owner_iss: pr.agent_iss.clone(),
            owner_sub: pr.agent_sub.clone(),
            person_id: person_id.to_string(),
            blob: bytes.clone(),
            approved_at: now,
            expires_at,
            state: "active".into(),
            termination_reason: None,
        })
        .map_err(|e| e.to_string())?;
    // A person token for each approved resource, and consent on record for
    // it (so a later request under the mission answers directly).
    let cnf_jwk: aauth_core::jwk::Jwk = serde_json::from_value(
        pr.payload
            .get("cnf_jwk")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|_| "pending request has no usable cnf_jwk".to_string())?;
    let agent_token_exp = pr
        .payload
        .get("agent_token_exp")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let mut person_tokens = serde_json::Map::new();
    for r in &resources {
        app.store
            .grant_consent(
                person_id,
                &pr.agent_iss,
                &pr.agent_sub,
                r,
                "person",
                None,
                expires_at,
            )
            .map_err(|e| e.to_string())?;
        // A resource may be declined individually (e.g. the agent token
        // expires too soon); the agent may request it later.
        if let Ok(issued) = issue::person_token(
            app,
            &PersonTokenRequest {
                person_id,
                agent_iss: &pr.agent_iss,
                agent_sub: &pr.agent_sub,
                cnf_jwk: &cnf_jwk,
                audience: r,
                agent_token_exp,
                mission_expires_at: expires_at,
                mission_s256: Some(&s256),
                tenant: None,
            },
        ) {
            app.record(
                Some(person_id),
                &format!("agent:{}", pr.agent_sub),
                "person_token_issued",
                Some(r),
                serde_json::json!({ "agent_iss": pr.agent_iss, "jti": issued.jti, "exp": issued.exp,
                                    "mission_s256": s256, "via": via }),
            );
            person_tokens.insert(r.clone(), issued.token.into());
        }
    }
    let mut response = serde_json::json!({
        "s256": s256,
        "mission": aauth_core::b64::encode(&bytes),
    });
    if !person_tokens.is_empty() {
        response["person_tokens"] = serde_json::Value::Object(person_tokens);
    }
    if !app
        .store
        .decide_pending(
            &pr.id,
            "approved",
            Some(&serde_json::json!({ "response": response })),
        )
        .map_err(|e| e.to_string())?
    {
        return Ok(ApproveOutcome::Expired);
    }
    app.pending_notify.decided(&pr.id);
    app.record(
        Some(person_id),
        "person",
        "mission_approved",
        Some(&s256),
        serde_json::json!({ "agent_iss": pr.agent_iss, "agent_sub": pr.agent_sub, "expires_at": expires_at,
                            "resources": resources, "via": via }),
    );
    Ok(ApproveOutcome::Approved {
        jti: s256,
        exp: expires_at.unwrap_or(0),
    })
}

/// Accept a completion proposal: the mission terminates as `completed`.
fn approve_completion(
    app: &Arc<App>,
    person_id: &str,
    pr: &Pending,
    via: &str,
) -> Result<ApproveOutcome, String> {
    let s256 = pr
        .payload
        .get("mission_s256")
        .and_then(|v| v.as_str())
        .ok_or("completion request has no mission")?
        .to_string();
    let summary = pr
        .payload
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let terminated = app
        .store
        .terminate_mission(&s256, "completed")
        .map_err(|e| e.to_string())?;
    if terminated {
        app.store
            .append_mission_log(&s256, "completed", summary.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let response = serde_json::json!({ "s256": s256, "termination_reason": "completed" });
    if !app
        .store
        .decide_pending(
            &pr.id,
            "approved",
            Some(&serde_json::json!({ "response": response })),
        )
        .map_err(|e| e.to_string())?
    {
        return Ok(ApproveOutcome::Expired);
    }
    app.pending_notify.decided(&pr.id);
    app.record(
        Some(person_id),
        "person",
        "mission_completed",
        Some(&s256),
        serde_json::json!({ "agent_iss": pr.agent_iss, "agent_sub": pr.agent_sub, "via": via }),
    );
    Ok(ApproveOutcome::Approved { jti: s256, exp: 0 })
}

/// Deny `pr` as `person_id`.
pub fn deny(app: &Arc<App>, person_id: &str, pr: &Pending, via: &str) -> Result<(), String> {
    app.store
        .decide_pending(&pr.id, "denied", None)
        .map_err(|e| e.to_string())?;
    app.pending_notify.decided(&pr.id);
    app.record(
        Some(person_id),
        "person",
        "consent_denied",
        pr.payload.get("resource").and_then(|v| v.as_str()),
        serde_json::json!({ "agent_iss": pr.agent_iss, "agent_sub": pr.agent_sub, "pending_id": pr.id, "via": via }),
    );
    Ok(())
}
