//! Token revocation, both directions (§Token Revocation).
//!
//! **Inbound** — `POST /revoke`: an Agent Provider revokes an agent token it
//! issued, signing as itself with the `jwks_uri` scheme and naming the token
//! by `(iss, jti)`. We accept a revocation only from the issuer of the token
//! being revoked; on success we deny every later request presenting that
//! agent token, and revoke the auth tokens we issued for that agent by
//! calling each resource's `revocation_endpoint`.
//!
//! **Outbound** — [`revoke_auth_tokens_for_agent`]: for every live auth token
//! we issued for an agent, POST `{iss, jti}` to the resource's advertised
//! `revocation_endpoint`, signed as ourselves (`jwks_uri`, `aauth-person.json`,
//! our active `kid`), under egress admission. Also run when the person
//! revokes a binding. Revocation shortens exposure; the token lifetime bounds
//! it (≤ 1 h) — that is why the local records are marked revoked whether or
//! not the resource could be reached.

use std::sync::Arc;

use aauth_core::{sig, sigkey};

use crate::app::App;
use crate::problem::{json_ok, ApiError, Resp};
use crate::reqctx::{self, ReqCtx};

/// `POST /revoke`.
pub async fn inbound(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let signer = reqctx::verify_server_request(ctx, app, true).await?;
    let body = ctx.parse_json()?;
    let iss = body
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("invalid_request", "iss is required"))?
        .to_string();
    let jti = body
        .get("jti")
        .and_then(|v| v.as_str())
        .filter(|j| !j.is_empty() && j.len() <= 512)
        .ok_or_else(|| ApiError::bad_request("invalid_request", "jti is required"))?
        .to_string();
    // Only the issuer of the token may revoke it (or a trusted PS — none are
    // configured in this build).
    if signer.id != iss {
        app.audit.emit(
            "revocation_refused",
            serde_json::json!({ "signer": signer.id, "iss": iss, "jti": jti, "reason": "not_issuer" }),
        );
        return Err(ApiError::forbidden(
            "forbidden",
            "a revocation is accepted only from the issuer of the token being revoked",
        ));
    }
    if iss == app.cfg.issuer {
        // Someone signing as us revoking our own token: only we hold our
        // key, so this is an operator tool at most. Mark and answer.
        return match app.store.auth_token_record(&jti)? {
            Some(_) => {
                app.store.mark_auth_token_revoked(&jti)?;
                app.audit.emit(
                    "auth_token_revoked",
                    serde_json::json!({ "jti": jti, "via": "revocation_endpoint" }),
                );
                Ok(json_ok(&serde_json::json!({ "revoked": true })))
            }
            None => Err(ApiError::not_found(
                "not_found",
                "no token with that (iss, jti) is known here",
            )),
        };
    }
    // An Agent Provider revoking an agent token. We may never have seen the
    // token; record the revocation regardless so a later presentation is
    // denied (200: "revoked or already invalid").
    let seen = app.store.agent_token_seen(&iss, &jti)?;
    let purge_after = seen
        .as_ref()
        .map(|(_, exp)| *exp)
        .unwrap_or(aauth_core::now_unix() + aauth_core::tokens::AGENT_TOKEN_MAX_TTL_SECS)
        + 3600;
    let fresh = app.store.revoke_agent_token(&iss, &jti, purge_after)?;
    // Attribute it to the person the agent is bound to, so "your agent
    // provider revoked a token for this agent" shows on their dashboard.
    let person = match &seen {
        Some((sub, _)) => app
            .store
            .binding(&iss, sub)?
            .filter(|b| b.is_active())
            .map(|b| b.person_id),
        None => None,
    };
    app.record(
        person.as_deref(),
        &format!("ap:{iss}"),
        "agent_token_revoked",
        seen.as_ref().map(|(sub, _)| sub.as_str()),
        serde_json::json!({ "iss": iss, "jti": jti, "seen": seen.is_some(), "fresh": fresh,
                            "note": "the agent provider revoked one of this agent's tokens; the binding is unchanged" }),
    );
    // SHOULD: revoke the auth tokens we issued for that agent.
    if let Some((agent_sub, _)) = seen {
        let app2 = app.clone();
        let iss2 = iss.clone();
        tokio::spawn(async move {
            revoke_auth_tokens_for_agent(&app2, &iss2, &agent_sub, "agent_token_revoked_by_ap")
                .await;
        });
    }
    Ok(json_ok(&serde_json::json!({ "revoked": true })))
}

/// Outcome summary of an outbound revocation sweep.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RevocationSweep {
    pub tokens: usize,
    pub notified: usize,
    pub failed: usize,
}

/// Revoke every live auth token we issued for `(agent_iss, agent_sub)`:
/// mark locally, and tell each resource that advertises a
/// `revocation_endpoint`.
pub async fn revoke_auth_tokens_for_agent(
    app: &Arc<App>,
    agent_iss: &str,
    agent_sub: &str,
    reason: &str,
) -> RevocationSweep {
    let live = match app.store.live_auth_tokens_for_agent(agent_iss, agent_sub) {
        Ok(v) => v,
        Err(e) => {
            app.audit.emit(
                "revocation_sweep_failed",
                serde_json::json!({ "agent_iss": agent_iss, "agent_sub": agent_sub, "error": e.to_string() }),
            );
            return RevocationSweep::default();
        }
    };
    revoke_auth_tokens(app, live, reason).await
}

/// Revoke every live auth token issued under a mission.
pub async fn revoke_auth_tokens_for_mission(
    app: &Arc<App>,
    s256: &str,
    reason: &str,
) -> RevocationSweep {
    let live = match app.store.live_auth_tokens_for_mission(s256) {
        Ok(v) => v,
        Err(e) => {
            app.audit.emit(
                "revocation_sweep_failed",
                serde_json::json!({ "mission_s256": s256, "error": e.to_string() }),
            );
            return RevocationSweep::default();
        }
    };
    revoke_auth_tokens(app, live, reason).await
}

/// Mark each token revoked locally and tell its resource.
pub async fn revoke_auth_tokens(
    app: &Arc<App>,
    live: Vec<crate::store::AuthTokenRecord>,
    reason: &str,
) -> RevocationSweep {
    let mut sweep = RevocationSweep::default();
    for rec in live {
        let (agent_iss, agent_sub) = (rec.agent_iss.clone(), rec.agent_sub.clone());
        sweep.tokens += 1;
        let _ = app.store.mark_auth_token_revoked(&rec.jti);
        let token_iss = rec.iss.clone().unwrap_or_else(|| app.cfg.issuer.clone());
        match notify_resource(app, &rec.aud, &token_iss, &rec.jti).await {
            Ok(status) => {
                sweep.notified += 1;
                app.record(
                    Some(&rec.person_id),
                    "psd",
                    "auth_token_revoked",
                    Some(&rec.aud),
                    serde_json::json!({ "jti": rec.jti, "agent_iss": agent_iss, "agent_sub": agent_sub,
                                        "reason": reason, "resource_status": status }),
                );
            }
            Err(e) => {
                sweep.failed += 1;
                app.record(
                    Some(&rec.person_id),
                    "psd",
                    "auth_token_revocation_not_delivered",
                    Some(&rec.aud),
                    serde_json::json!({ "jti": rec.jti, "agent_iss": agent_iss, "agent_sub": agent_sub,
                                        "reason": reason, "error": e,
                                        "note": "the token expires on its own within its lifetime" }),
                );
            }
        }
    }
    sweep
}

/// Tell `resource` that our auth token `jti` is revoked. Returns the HTTP
/// status the resource answered with. Discovers `revocation_endpoint` from
/// the resource's metadata; a resource without one cannot be told.
async fn notify_resource(
    app: &Arc<App>,
    resource: &str,
    token_iss: &str,
    jti: &str,
) -> Result<u16, String> {
    let meta = app
        .jwks_cache
        .get_metadata(resource, "aauth-resource.json")
        .await
        .map_err(|e| format!("metadata: {e}"))?;
    let endpoint = meta
        .get("revocation_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "resource advertises no revocation_endpoint".to_string())?
        .to_string();
    if !(endpoint.starts_with("https://")
        || (app.cfg.insecure_dev_mode && endpoint.starts_with("http://")))
    {
        return Err("revocation_endpoint is not https".into());
    }
    let (authority, path) = crate::httpc::signing_parts(&endpoint)?;
    let body = serde_json::json!({ "iss": token_iss, "jti": jti }).to_string();
    let digest = reqctx::content_digest_sha256(body.as_bytes());
    let headers_for_sig = [
        ("content-type".to_string(), "application/json".to_string()),
        ("content-digest".to_string(), digest.clone()),
    ];
    let lookup = move |name: &str| {
        headers_for_sig
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    let scheme =
        sigkey::serialize_jwks_uri(&app.cfg.issuer, "aauth-person.json", &app.keys.active_kid);
    let signed = sig::sign_request(
        "POST",
        &authority,
        &path,
        "",
        &["content-type", "content-digest"],
        &lookup,
        &scheme,
        &app.keys.active_key,
        aauth_core::now_unix(),
    )
    .map_err(|e| format!("sign: {e}"))?;
    let headers = vec![
        ("content-digest".to_string(), digest),
        ("signature-input".to_string(), signed.signature_input),
        ("signature".to_string(), signed.signature),
        ("signature-key".to_string(), signed.signature_key),
    ];
    let status = crate::httpc::post_json(&endpoint, body.as_bytes(), &headers, &app.egress).await?;
    if status == 200 || status == 404 {
        // 200: revoked or already invalid; 404: the resource never had it —
        // either way nothing more to do.
        Ok(status)
    } else {
        Err(format!("resource answered HTTP {status}"))
    }
}
