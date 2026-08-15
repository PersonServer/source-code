//! Unsigned discovery documents: PS metadata, JWKS, health.

use std::sync::Arc;

use hyper::body::Bytes;

use crate::app::App;
use crate::problem::{json_cacheable, json_ok, Resp};

/// `/.well-known/aauth-person.json` — cacheable, `issuer` = our own URL.
pub fn person_metadata(app: &Arc<App>) -> Resp {
    json_cacheable(Bytes::from(app.person_metadata_bytes.clone()), 300)
}

/// `/.well-known/jwks.json` — every key carries a fully-specified `alg`.
pub fn jwks(app: &Arc<App>) -> Resp {
    json_cacheable(Bytes::from(app.jwks_bytes.clone()), 300)
}

pub fn healthz(app: &Arc<App>) -> Resp {
    json_ok(&serde_json::json!({
        "status": "ok",
        "issuer": app.cfg.issuer,
        "uptime_secs": aauth_core::now_unix().saturating_sub(app.started_at),
    }))
}
