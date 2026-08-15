//! Request routing: method + path → handler, with every error normalized to
//! RFC 9457 problem+json. Unsigned well-known documents and static assets are
//! served before a body is read; everything else goes through
//! [`ReqCtx::read`] and [`dispatch`], which is also the seam the in-process
//! tests use.
//!
//! The two front doors meet only here: `/.well-known/*`, `/person`,
//! `/token`, `/revoke`, `/mission*`, `/interaction`, `/pending/*` are the
//! AAuth-signed machine surface; `/`, `/login*`, `/logout`, `/enrol/*`,
//! `/agents/*`, `/activity`, `/passkeys*`, `/consent/*` are the
//! session-authenticated human UI. No handler serves both.

use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Method, Request, StatusCode};

use crate::app::App;
use crate::handlers::{tokens, ui as uih, wellknown};
use crate::problem::{ApiError, Resp};
use crate::reqctx::ReqCtx;

pub async fn route(req: Request<Incoming>, app: Arc<App>) -> Resp {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Well-known documents and static assets are unsigned GETs; serve them
    // before reading a body.
    match (&method, path.as_str()) {
        (&Method::GET, "/.well-known/aauth-person.json") => {
            return wellknown::person_metadata(&app)
        }
        (&Method::GET, "/.well-known/jwks.json") => return wellknown::jwks(&app),
        (&Method::GET, "/healthz") => return wellknown::healthz(&app),
        (&Method::GET, p) if p.starts_with("/static/") => {
            if let Some(resp) = crate::ui::static_asset(p) {
                return resp;
            }
        }
        _ => {}
    }

    let ctx = match ReqCtx::read(req, app.cfg.max_body_bytes).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    match dispatch(&method, &path, &ctx, &app).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

pub(crate) async fn dispatch(
    method: &Method,
    path: &str,
    ctx: &ReqCtx,
    app: &Arc<App>,
) -> Result<Resp, ApiError> {
    match (method, path) {
        // Machine surface (AAuth-signed).
        (&Method::POST, "/person") => tokens::person_token(ctx, app).await,
        (&Method::POST, "/token") => tokens::auth_token(ctx, app).await,
        (&Method::POST, "/revoke") => crate::revocation::inbound(ctx, app).await,
        (&Method::POST, "/mission") => crate::handlers::mission::propose(ctx, app).await,

        // Human surface (session).
        (&Method::GET, "/") => uih::dashboard(ctx, app).await,
        (&Method::GET, "/login") => uih::login_page(ctx, app).await,
        (&Method::POST, "/login/options") => uih::login_options(ctx, app).await,
        (&Method::POST, "/login/finish") => uih::login_finish(ctx, app).await,
        (&Method::POST, "/logout") => uih::logout(ctx, app).await,
        (&Method::GET, "/activity") => uih::activity(ctx, app).await,
        (&Method::POST, "/agents/revoke") => uih::revoke_agent(ctx, app).await,
        (&Method::POST, "/missions/end") => uih::end_mission(ctx, app).await,
        (&Method::GET, "/passkeys") => uih::passkeys_page(ctx, app).await,
        (&Method::GET, "/passkeys/add") => uih::passkey_add_page(ctx, app).await,
        (&Method::POST, "/passkeys/options") => uih::passkey_add_options(ctx, app).await,
        (&Method::POST, "/passkeys/finish") => uih::passkey_add_finish(ctx, app).await,
        (&Method::GET, "/consent") => uih::consent_entry(ctx, app).await,

        _ => {
            if let Some(s256) = path.strip_prefix("/mission/") {
                if method == Method::POST && !s256.is_empty() && !s256.contains('/') {
                    return crate::handlers::mission::act(ctx, app, s256).await;
                }
            }
            if let Some(id) = path.strip_prefix("/pending/") {
                if method == Method::GET && !id.is_empty() && !id.contains('/') {
                    return tokens::poll(ctx, app, id).await;
                }
            }
            if let Some(id) = path.strip_prefix("/consent/") {
                if !id.is_empty() && !id.contains('/') {
                    match *method {
                        Method::GET => return uih::consent_page(ctx, app, id).await,
                        Method::POST => return uih::consent_decide(ctx, app, id).await,
                        _ => {}
                    }
                }
            }
            if let Some(rest) = path.strip_prefix("/enrol/") {
                let (token, action) = match rest.split_once('/') {
                    Some((t, a)) => (t, Some(a)),
                    None => (rest, None),
                };
                if !token.is_empty() && !token.contains('/') {
                    match (method, action) {
                        (&Method::GET, None) => return uih::enrol_page(ctx, app, token).await,
                        (&Method::POST, Some("options")) => {
                            return uih::enrol_options(ctx, app, token).await
                        }
                        (&Method::POST, Some("finish")) => {
                            return uih::enrol_finish(ctx, app, token).await
                        }
                        _ => {}
                    }
                }
            }
            Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                format!("no route for {method} {path}"),
            ))
        }
    }
}
