//! Reaching the person when a decision is pending. Channels are a deployment
//! choice, not protocol. `web` is always on: a claimed request appears on the dashboard
//! and the agent relays the interaction code. `webhook` additionally POSTs a
//! JSON notification to `notify.webhook_url` under the same egress admission
//! as every other outbound request. The webhook carries the consent URL (which
//! needs a session) and never the interaction code.

use std::sync::Arc;

use crate::app::App;
use crate::store::Pending;

pub async fn pending_created(app: &Arc<App>, pr: &Pending) {
    if !app.cfg.notify.channels.iter().any(|c| c == "webhook") {
        return;
    }
    let Some(url) = app.cfg.notify.webhook_url.clone() else {
        return;
    };
    let body = serde_json::json!({
        "event": "pending_request",
        "id": pr.id,
        "kind": pr.kind,
        "agent_iss": pr.agent_iss,
        "agent_sub": pr.agent_sub,
        "person_id": pr.person_id,
        "resource": pr.payload.get("resource"),
        "consent_url": format!("{}/consent/{}", app.cfg.issuer, pr.id),
        "expires_at": pr.expires_at,
    });
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    // Fire and forget: a slow webhook must not delay the agent's 202.
    let egress = app.egress.clone();
    let audit_app = app.clone();
    let id = pr.id.clone();
    tokio::spawn(async move {
        match crate::httpc::post_json(&url, &bytes, &[], &egress).await {
            Ok(status) if (200..300).contains(&status) => {}
            Ok(status) => audit_app.audit.emit(
                "webhook_failed",
                serde_json::json!({ "pending_id": id, "status": status }),
            ),
            Err(e) => audit_app.audit.emit(
                "webhook_failed",
                serde_json::json!({ "pending_id": id, "error": e }),
            ),
        }
    });
}
