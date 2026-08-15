//! The human front door: session-authenticated HTML pages and the two passkey
//! ceremony JSON endpoints. Nothing here can mint a token or touch the
//! agent-facing verification path: two front doors, one core.
//!
//! Routes:
//! - `GET /enrol/{token}` · `POST /enrol/{token}/options|finish` — first
//!   passkey, via a one-time link from `psd person add` / `psd invite`
//! - `GET /login` · `POST /login/options|finish` · `POST /logout`
//! - `GET /` dashboard · `GET /activity` · `POST /agents/revoke`
//! - `GET /passkeys` · `GET /passkeys/add` · `POST /passkeys/options|finish`
//! - `GET /consent[?code=]` (the interaction URL) · `GET /consent/{id}` ·
//!   `POST /consent/{id}` — the decision screen
//! - `GET /static/*`
//!
//! Every state-changing POST checks the session's CSRF token (form field
//! `csrf` or `X-CSRF` header). Errors on HTML routes render `error.html`;
//! errors on the JSON ceremony routes are problem+json.

use std::sync::Arc;

use hyper::StatusCode;
use minijinja::{context, Value};

use crate::app::App;
use crate::passkey::Passkeys;
use crate::problem::{json_ok, ApiError, Resp};
use crate::reqctx::ReqCtx;
use crate::store::{Person, Session};
use crate::ui;

/// The authenticated person behind a request.
pub struct Login {
    pub sid: String,
    pub session: Session,
    pub person: Person,
}

fn base(app: &App, login: Option<&Login>) -> Value {
    context! {
        ps_name => app.cfg.metadata.name.clone().unwrap_or_else(|| "Person Server".into()),
        issuer => app.cfg.issuer.clone(),
        version => env!("CARGO_PKG_VERSION"),
        person => login.map(|l| context! { id => l.person.id.clone(), display_name => l.person.display_name.clone() }),
        csrf => login.map(|l| l.session.csrf.clone()).unwrap_or_default(),
    }
}

/// The current login, if the request carries a valid session cookie.
pub fn current_login(ctx: &ReqCtx, app: &App) -> Result<Option<Login>, ApiError> {
    let Some(sid) = ui::session_id(ctx) else {
        return Ok(None);
    };
    let Some(session) = app.store.get_session(&sid)? else {
        return Ok(None);
    };
    let Some(person) = app.store.get_person(&session.person_id)? else {
        return Ok(None);
    };
    Ok(Some(Login {
        sid,
        session,
        person,
    }))
}

/// Require a login for an HTML page; otherwise a redirect to `/login?next=`
/// (boxed: a `Response` is a large `Err` to carry around).
fn require_login(ctx: &ReqCtx, app: &App) -> Result<Login, Box<Resp>> {
    match current_login(ctx, app) {
        Ok(Some(l)) => Ok(l),
        Ok(None) => {
            let next = format!("{}{}", ctx.path, ctx.query);
            Err(Box::new(ui::redirect(&format!(
                "/login?next={}",
                percent_encode(&next)
            ))))
        }
        Err(e) => Err(Box::new(page_err(app, None, e))),
    }
}

/// Require a login for a JSON endpoint (401 problem otherwise).
fn require_login_json(ctx: &ReqCtx, app: &App) -> Result<Login, ApiError> {
    current_login(ctx, app)?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "login_required", "sign in first"))
}

fn require_csrf(
    ctx: &ReqCtx,
    login: &Login,
    form: Option<&std::collections::HashMap<String, String>>,
) -> Result<(), ApiError> {
    match ui::presented_csrf(ctx, form) {
        Some(t) if ui::ct_eq(&t, &login.session.csrf) => Ok(()),
        _ => Err(ApiError::forbidden(
            "csrf",
            "the request did not carry the session's CSRF token; reload the page and try again",
        )),
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn page_err(app: &App, login: Option<&Login>, err: ApiError) -> Resp {
    ui::api_error_to_page(&app.templates, base(app, login), err)
}

fn passkeys(app: &App) -> Result<&Passkeys, ApiError> {
    app.passkeys.as_ref().ok_or_else(|| {
        ApiError::server_error(
            "passkeys are unavailable: the issuer host is an IP address, and WebAuthn needs a \
             domain (use a hostname such as http://localhost:8430 in development)",
        )
    })
}

fn render(app: &App, name: &str, ctx: Value) -> Result<Resp, ApiError> {
    let body = app
        .templates
        .render(name, ctx)
        .map_err(ApiError::server_error)?;
    Ok(ui::html(StatusCode::OK, body))
}

/// A WebAuthn `user.name` from a display name: PRECIS-friendly ASCII.
fn webauthn_username(display_name: &str, fallback: &str) -> String {
    let s: String = display_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        fallback.to_string()
    } else {
        s
    }
}

// ------------------------------------------------------------------ enrolment

pub async fn enrol_page(ctx: &ReqCtx, app: &Arc<App>, token: &str) -> Result<Resp, ApiError> {
    let person = match app.store.peek_enrolment(token)? {
        Some(pid) => app.store.get_person(&pid)?,
        None => None,
    };
    let Some(person) = person else {
        return Ok(ui::error_page(
            &app.templates,
            base(app, None),
            StatusCode::NOT_FOUND,
            "This link is not valid",
            "The enrolment link is unknown, already used, or expired. Ask the operator for a \
             new one (`psd invite`).",
        ));
    };
    if let Err(e) = passkeys(app) {
        return Ok(page_err(app, None, e));
    }
    let _ = ctx;
    render(
        app,
        "enrol.html",
        context! { ..base(app, None), ..context! {
            display_name => person.display_name,
            adding => false,
            options_url => format!("/enrol/{token}/options"),
            finish_url => format!("/enrol/{token}/finish"),
        } },
    )
}

pub async fn enrol_options(_ctx: &ReqCtx, app: &Arc<App>, token: &str) -> Result<Resp, ApiError> {
    let pid = app
        .store
        .peek_enrolment(token)?
        .ok_or_else(|| ApiError::not_found("invalid_enrolment", "enrolment link is not valid"))?;
    let person = app
        .store
        .get_person(&pid)?
        .ok_or_else(|| ApiError::not_found("invalid_enrolment", "enrolment link is not valid"))?;
    registration_options(app, &person)
}

fn registration_options(app: &App, person: &Person) -> Result<Resp, ApiError> {
    let existing: Vec<Vec<u8>> = app
        .store
        .credentials_for_person(&person.id)?
        .into_iter()
        .map(|c| c.stored.cred_id)
        .collect();
    let options = passkeys(app)?
        .start_registration(
            &person.user_handle,
            &webauthn_username(&person.display_name, &person.id),
            &person.display_name,
            &existing,
        )
        .map_err(ApiError::server_error)?;
    Ok(json_ok(&options))
}

pub async fn enrol_finish(ctx: &ReqCtx, app: &Arc<App>, token: &str) -> Result<Resp, ApiError> {
    let pid = app
        .store
        .peek_enrolment(token)?
        .ok_or_else(|| ApiError::not_found("invalid_enrolment", "enrolment link is not valid"))?;
    let person = app
        .store
        .get_person(&pid)?
        .ok_or_else(|| ApiError::not_found("invalid_enrolment", "enrolment link is not valid"))?;
    let cred = passkeys(app)?
        .finish_registration(&ctx.body)
        .map_err(|e| ApiError::bad_request("registration_failed", e))?;
    if cred.user_handle != person.user_handle {
        return Err(ApiError::bad_request(
            "registration_failed",
            "the passkey was created for a different user handle",
        ));
    }
    // Consume the one-time link only once the ceremony has verified.
    if app.store.take_enrolment(token)?.is_none() {
        return Err(ApiError::new(
            StatusCode::GONE,
            "invalid_enrolment",
            "enrolment link was used or expired while registering",
        ));
    }
    app.store.add_credential(&person.id, &cred, None)?;
    app.record(
        Some(&person.id),
        "person",
        "passkey_registered",
        None,
        serde_json::json!({ "cred_id": aauth_core::b64::encode(&cred.cred_id), "via": "enrolment" }),
    );
    let (sid, _csrf) = app
        .store
        .create_session(&person.id, app.cfg.ui.session_ttl_secs)?;
    app.record(
        Some(&person.id),
        "person",
        "signed_in",
        None,
        serde_json::json!({ "via": "enrolment" }),
    );
    let resp = json_ok(&serde_json::json!({ "redirect": "/" }));
    Ok(ui::with_cookie(
        resp,
        ui::session_cookie(&app.cfg, &sid, app.cfg.ui.session_ttl_secs),
    ))
}

// ---------------------------------------------------------------- login/logout

pub async fn login_page(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let next = ui::safe_next(ui::query_param(ctx, "next").as_deref());
    if current_login(ctx, app)?.is_some() {
        return Ok(ui::redirect(&next));
    }
    if let Err(e) = passkeys(app) {
        return Ok(page_err(app, None, e));
    }
    render(
        app,
        "login.html",
        context! { ..base(app, None), ..context! { next } },
    )
}

pub async fn login_options(_ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let options = passkeys(app)?
        .start_authentication()
        .map_err(ApiError::server_error)?;
    Ok(json_ok(&options))
}

pub async fn login_finish(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let body = ctx.parse_json()?;
    let credential = body
        .get("credential")
        .ok_or_else(|| ApiError::bad_request("invalid_request", "credential is required"))?
        .to_string();
    let next = ui::safe_next(body.get("next").and_then(|v| v.as_str()));
    let store = &app.store;
    let lookup = |id: &[u8]| store.credential(id).ok().flatten().map(|c| c.stored);
    let outcome = passkeys(app)?
        .finish_authentication(credential.as_bytes(), &lookup)
        .map_err(|e| ApiError::new(StatusCode::UNAUTHORIZED, "authentication_failed", e))?;
    let cred = store.credential(&outcome.cred_id)?.ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "unknown credential",
        )
    })?;
    let person = store.get_person(&cred.person_id)?.ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "unknown person",
        )
    })?;
    store.touch_credential(&outcome.cred_id, outcome.updated_dynamic_state.as_deref())?;
    let (sid, _csrf) = store.create_session(&person.id, app.cfg.ui.session_ttl_secs)?;
    app.record(
        Some(&person.id),
        "person",
        "signed_in",
        None,
        serde_json::json!({ "cred_id": aauth_core::b64::encode(&outcome.cred_id) }),
    );
    let resp = json_ok(&serde_json::json!({ "redirect": next }));
    Ok(ui::with_cookie(
        resp,
        ui::session_cookie(&app.cfg, &sid, app.cfg.ui.session_ttl_secs),
    ))
}

pub async fn logout(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let login = match require_login(ctx, app) {
        Ok(l) => l,
        Err(resp) => return Ok(*resp),
    };
    let form = ui::parse_form(&ctx.body);
    if let Err(e) = require_csrf(ctx, &login, Some(&form)) {
        return Ok(page_err(app, Some(&login), e));
    }
    app.store.delete_session(&login.sid)?;
    Ok(ui::with_cookie(
        ui::redirect("/login"),
        ui::clear_session_cookie(&app.cfg),
    ))
}

// -------------------------------------------------------------------- pages

pub async fn dashboard(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let login = match require_login(ctx, app) {
        Ok(l) => l,
        Err(resp) => return Ok(*resp),
    };
    let bindings: Vec<Value> = app
        .store
        .bindings_for_person(&login.person.id)?
        .into_iter()
        .map(binding_value)
        .collect();
    let audit: Vec<Value> = app
        .store
        .recent_audit(Some(&login.person.id), 10)?
        .into_iter()
        .map(audit_value)
        .collect();
    let consents: Vec<Value> = app
        .store
        .consents_for_person(&login.person.id)?
        .into_iter()
        .map(|c| {
            context! {
                agent_sub => c.agent_sub, agent_iss => c.agent_iss, audience => c.audience,
                kind => c.kind, scope => c.scope, granted_at => c.granted_at,
            }
        })
        .collect();
    let mut missions: Vec<Value> = Vec::new();
    for m in app.store.missions_for_person(&login.person.id)? {
        let blob = m.blob_json();
        let log: Vec<Value> = app
            .store
            .mission_log(&m.s256)?
            .into_iter()
            .map(|e| {
                context! {
                    at => e.at, kind => e.kind,
                    body_html => crate::markdown::render(&String::from_utf8_lossy(&e.body)),
                }
            })
            .collect();
        missions.push(context! {
            s256 => m.s256, agent_sub => m.owner_sub, active => m.is_active(),
            termination_reason => m.termination_reason, approved_at => m.approved_at,
            expires_at => m.expires_at,
            description_html => crate::markdown::render(blob.get("description").and_then(|v| v.as_str()).unwrap_or("")),
            resources => blob.get("approved_resources").cloned().unwrap_or(serde_json::json!([])),
            log,
        });
    }
    let pending: Vec<Value> = app
        .store
        .pending_for_person(&login.person.id)?
        .into_iter()
        .map(|p| {
            context! {
                id => p.id,
                agent_sub => p.agent_sub,
                resource => p.payload.get("resource").and_then(|v| v.as_str()).map(|s| s.to_string()),
                created_at => p.created_at,
            }
        })
        .collect();
    render(
        app,
        "dashboard.html",
        context! { ..base(app, Some(&login)), ..context! { bindings, audit, pending, consents, missions } },
    )
}

pub async fn activity(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let login = match require_login(ctx, app) {
        Ok(l) => l,
        Err(resp) => return Ok(*resp),
    };
    let audit: Vec<Value> = app
        .store
        .recent_audit(Some(&login.person.id), 200)?
        .into_iter()
        .map(audit_value)
        .collect();
    render(
        app,
        "activity.html",
        context! { ..base(app, Some(&login)), ..context! { audit } },
    )
}

pub async fn revoke_agent(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let login = match require_login(ctx, app) {
        Ok(l) => l,
        Err(resp) => return Ok(*resp),
    };
    let form = ui::parse_form(&ctx.body);
    if let Err(e) = require_csrf(ctx, &login, Some(&form)) {
        return Ok(page_err(app, Some(&login), e));
    }
    let (Some(iss), Some(sub)) = (form.get("agent_iss"), form.get("agent_sub")) else {
        return Ok(page_err(
            app,
            Some(&login),
            ApiError::bad_request("invalid_request", "agent_iss and agent_sub are required"),
        ));
    };
    match app.store.binding(iss, sub)? {
        Some(b) if b.person_id == login.person.id => {
            if app.store.revoke_binding(iss, sub)? {
                app.store
                    .revoke_consents_for_agent(&login.person.id, iss, sub)?;
                let (app2, iss2, sub2) = (app.clone(), iss.clone(), sub.clone());
                tokio::spawn(async move {
                    crate::revocation::revoke_auth_tokens_for_agent(
                        &app2,
                        &iss2,
                        &sub2,
                        "binding_revoked_by_person",
                    )
                    .await;
                });
                app.record(
                    Some(&login.person.id),
                    "person",
                    "binding_revoked",
                    Some(sub),
                    serde_json::json!({ "agent_iss": iss, "agent_sub": sub, "via": "dashboard" }),
                );
            }
            Ok(ui::redirect("/"))
        }
        _ => Ok(page_err(
            app,
            Some(&login),
            ApiError::not_found("not_found", "no such agent is bound to you"),
        )),
    }
}

/// `POST /missions/end` — the person ends a mission (`revoked`).
pub async fn end_mission(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let login = match require_login(ctx, app) {
        Ok(l) => l,
        Err(resp) => return Ok(*resp),
    };
    let form = ui::parse_form(&ctx.body);
    if let Err(e) = require_csrf(ctx, &login, Some(&form)) {
        return Ok(page_err(app, Some(&login), e));
    }
    let Some(s256) = form.get("s256") else {
        return Ok(page_err(
            app,
            Some(&login),
            ApiError::bad_request("invalid_request", "s256 is required"),
        ));
    };
    match app.store.mission(s256)? {
        Some(m) if m.person_id == login.person.id => {
            crate::handlers::mission::terminate(app, s256, "revoked", "person").await?;
            Ok(ui::redirect("/"))
        }
        _ => Ok(page_err(
            app,
            Some(&login),
            ApiError::not_found("not_found", "no such mission of yours"),
        )),
    }
}

pub async fn passkeys_page(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let login = match require_login(ctx, app) {
        Ok(l) => l,
        Err(resp) => return Ok(*resp),
    };
    let credentials: Vec<Value> = app
        .store
        .credentials_for_person(&login.person.id)?
        .into_iter()
        .map(|c| {
            let id = aauth_core::b64::encode(&c.stored.cred_id);
            context! {
                cred_id_short => id.chars().take(8).collect::<String>(),
                nickname => c.nickname,
                created_at => c.created_at,
                last_used_at => c.last_used_at,
            }
        })
        .collect();
    render(
        app,
        "passkeys.html",
        context! { ..base(app, Some(&login)), ..context! { credentials } },
    )
}

pub async fn passkey_add_page(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let login = match require_login(ctx, app) {
        Ok(l) => l,
        Err(resp) => return Ok(*resp),
    };
    if let Err(e) = passkeys(app) {
        return Ok(page_err(app, Some(&login), e));
    }
    render(
        app,
        "enrol.html",
        context! { ..base(app, Some(&login)), ..context! {
            display_name => login.person.display_name.clone(),
            adding => true,
            options_url => "/passkeys/options",
            finish_url => "/passkeys/finish",
        } },
    )
}

pub async fn passkey_add_options(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let login = require_login_json(ctx, app)?;
    require_csrf(ctx, &login, None)?;
    registration_options(app, &login.person)
}

pub async fn passkey_add_finish(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let login = require_login_json(ctx, app)?;
    require_csrf(ctx, &login, None)?;
    let cred = passkeys(app)?
        .finish_registration(&ctx.body)
        .map_err(|e| ApiError::bad_request("registration_failed", e))?;
    if cred.user_handle != login.person.user_handle {
        return Err(ApiError::bad_request(
            "registration_failed",
            "the passkey was created for a different user handle",
        ));
    }
    app.store.add_credential(&login.person.id, &cred, None)?;
    app.record(
        Some(&login.person.id),
        "person",
        "passkey_registered",
        None,
        serde_json::json!({ "cred_id": aauth_core::b64::encode(&cred.cred_id), "via": "dashboard" }),
    );
    Ok(json_ok(&serde_json::json!({ "redirect": "/passkeys" })))
}

// ------------------------------------------------------------------- consent

/// `GET /consent[?code=XXXX-XXXX]` — the interaction URL. With a code: locate
/// the pending request, claim it for this person (consuming the code) and
/// redirect to its decision page. Without: a form to type the code.
pub async fn consent_entry(ctx: &ReqCtx, app: &Arc<App>) -> Result<Resp, ApiError> {
    let login = match require_login(ctx, app) {
        Ok(l) => l,
        Err(resp) => return Ok(*resp),
    };
    let Some(code) = ui::query_param(ctx, "code").filter(|c| !c.trim().is_empty()) else {
        return render(
            app,
            "consent_code.html",
            context! { ..base(app, Some(&login)), ..context! { error => Value::UNDEFINED } },
        );
    };
    if !app
        .code_attempts
        .allowed(&login.person.id, app.cfg.limits.code_attempts)
    {
        return Ok(ui::error_page(
            &app.templates,
            base(app, Some(&login)),
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts",
            "Too many codes were tried recently. Wait a few minutes, then ask the agent for a \
             fresh request.",
        ));
    }
    let hash = crate::pending::code_hash(&code);
    let found = app.store.pending_by_code(&hash)?;
    let Some(pr) = found else {
        app.code_attempts.failed(&login.person.id);
        app.record(
            Some(&login.person.id),
            "person",
            "interaction_code_rejected",
            None,
            serde_json::json!({}),
        );
        return render(
            app,
            "consent_code.html",
            context! { ..base(app, Some(&login)), ..context! {
                error => "That code is not recognised, has expired, or was already used. Codes are single-use; ask the agent to start again if needed."
            } },
        );
    };
    match app.store.claim_pending(&pr.id, &login.person.id)? {
        Some(claimed) => {
            app.code_attempts.succeeded(&login.person.id);
            Ok(ui::redirect(&format!("/consent/{}", claimed.id)))
        }
        None => Ok(ui::error_page(
            &app.templates,
            base(app, Some(&login)),
            StatusCode::CONFLICT,
            "Not yours to decide",
            "This request is already being handled by another person, or it has expired.",
        )),
    }
}

/// `GET /consent/{id}` — the decision screen for a request this person has
/// claimed.
pub async fn consent_page(ctx: &ReqCtx, app: &Arc<App>, id: &str) -> Result<Resp, ApiError> {
    let login = match require_login(ctx, app) {
        Ok(l) => l,
        Err(resp) => return Ok(*resp),
    };
    let pr = match app.store.pending(id)? {
        Some(p) if p.person_id.as_deref() == Some(login.person.id.as_str()) => p,
        Some(p) if p.person_id.is_none() && p.is_open() => {
            // Unclaimed: the person must arrive with the code, not the id.
            return Ok(ui::redirect("/consent"));
        }
        _ => {
            return Ok(page_err(
                app,
                Some(&login),
                ApiError::not_found("not_found", "no such request is waiting for you"),
            ))
        }
    };
    if !pr.is_open() {
        return Ok(ui::error_page(
            &app.templates,
            base(app, Some(&login)),
            StatusCode::GONE,
            "Already decided",
            &format!(
                "This request is {} — there is nothing left to decide.",
                pr.state
            ),
        ));
    }
    let payload = &pr.payload;
    let resource_meta = payload.get("resource_meta").filter(|m| !m.is_null()).map(|m| {
        context! {
            name => m.get("name").and_then(|v| v.as_str()),
            description_html => m.get("description").and_then(|v| v.as_str()).map(crate::markdown::render),
            access_mode => m.get("access_mode").and_then(|v| v.as_str()).unwrap_or("agent-token"),
            logo_uri => m.get("logo_uri").and_then(|v| v.as_str()),
        }
    });
    // Auth requests: the scopes asked for, each with the resource's own
    // (sanitized) description when it publishes one.
    let scope_descriptions = payload
        .get("resource_meta")
        .and_then(|m| m.get("scope_descriptions"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let scopes: Vec<Value> = payload
        .get("requested_scopes")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(|sc| {
                    context! {
                        name => sc,
                        description_html => scope_descriptions
                            .get(sc)
                            .and_then(|d| d.as_str())
                            .map(crate::markdown::render),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let justification_html = payload
        .get("justification")
        .and_then(|v| v.as_str())
        .map(crate::markdown::render);
    // Mission proposals and completions.
    let mission = match pr.kind.as_str() {
        "mission" => Some(context! {
            description_html => payload.get("description").and_then(|v| v.as_str()).map(crate::markdown::render),
            tools => payload.get("tools").cloned().unwrap_or(serde_json::json!([])),
            resources => payload.get("resource_metas").cloned().unwrap_or(serde_json::json!([])),
        }),
        "mission_completion" => {
            let s256 = payload
                .get("mission_s256")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let description = app
                .store
                .mission(s256)?
                .map(|m| {
                    m.blob_json()
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                })
                .unwrap_or_default();
            Some(context! {
                s256,
                description_html => crate::markdown::render(&description),
                summary_html => payload.get("summary").and_then(|v| v.as_str()).map(crate::markdown::render),
            })
        }
        _ => None,
    };
    let details = serde_json::json!({
        "agent": { "iss": pr.agent_iss, "sub": pr.agent_sub, "ps": payload.get("agent_ps") },
        "subagent": payload.get("subagent_sub"),
        "resource": payload.get("resource"),
        "resource_metadata": payload.get("resource_meta"),
        "token_will_bind_key": payload.get("cnf_jwk"),
        "agent_token_expires": payload.get("agent_token_exp"),
        "requested_at": pr.created_at,
    });
    render(
        app,
        "consent.html",
        context! { ..base(app, Some(&login)), ..context! {
            pending_id => pr.id,
            kind => pr.kind,
            scopes,
            justification_html,
            mission,
            chained => payload.get("chained").cloned().filter(|c| !c.is_null()),
            new_agent => payload.get("new_agent").and_then(|v| v.as_bool()).unwrap_or(true),
            agent_iss => pr.agent_iss,
            agent_sub => pr.agent_sub,
            subagent_sub => payload.get("subagent_sub").and_then(|v| v.as_str()),
            ap_name => payload.get("ap_name").and_then(|v| v.as_str()),
            ap_logo_uri => payload.get("ap_logo_uri").and_then(|v| v.as_str()),
            platform => payload.get("platform").and_then(|v| v.as_str()),
            device => payload.get("device").and_then(|v| v.as_str()),
            resource => payload.get("resource").and_then(|v| v.as_str()),
            resource_meta,
            details_json => serde_json::to_string_pretty(&details).unwrap_or_default(),
        } },
    )
}

/// `POST /consent/{id}` — record the decision (`action=approve|deny`).
pub async fn consent_decide(ctx: &ReqCtx, app: &Arc<App>, id: &str) -> Result<Resp, ApiError> {
    let login = match require_login(ctx, app) {
        Ok(l) => l,
        Err(resp) => return Ok(*resp),
    };
    let form = ui::parse_form(&ctx.body);
    if let Err(e) = require_csrf(ctx, &login, Some(&form)) {
        return Ok(page_err(app, Some(&login), e));
    }
    let pr = match app.store.pending(id)? {
        Some(p) if p.person_id.as_deref() == Some(login.person.id.as_str()) && p.is_open() => p,
        _ => {
            return Ok(page_err(
                app,
                Some(&login),
                ApiError::not_found(
                    "not_found",
                    "no open request with that id is waiting for you",
                ),
            ))
        }
    };
    let resource = pr
        .payload
        .get("resource")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let kind = pr.kind.clone();
    match form.get("action").map(|s| s.as_str()) {
        Some("deny") => {
            crate::consent::deny(app, &login.person.id, &pr, "consent")
                .map_err(ApiError::server_error)?;
            render(
                app,
                "consent_done.html",
                context! { ..base(app, Some(&login)), ..context! { approved => false, agent_sub => pr.agent_sub, resource, kind } },
            )
        }
        Some("approve") => {
            let outcome = if pr.kind == "mission" {
                // The person's choice of lifetime; "never" means no expiry.
                let expires_in = match form.get("expires").map(|s| s.as_str()) {
                    Some("never") => None,
                    Some(v) => Some(
                        v.parse::<u64>()
                            .unwrap_or(app.cfg.missions.default_ttl_secs),
                    ),
                    None => Some(app.cfg.missions.default_ttl_secs),
                };
                crate::consent::approve_mission(app, &login.person.id, &pr, "consent", expires_in)
            } else {
                crate::consent::approve(app, &login.person.id, &pr, "consent")
            }
            .map_err(ApiError::server_error)?;
            match outcome {
                crate::consent::ApproveOutcome::Approved { .. } => render(
                    app,
                    "consent_done.html",
                    context! { ..base(app, Some(&login)), ..context! { approved => true, agent_sub => pr.agent_sub, resource, kind } },
                ),
                crate::consent::ApproveOutcome::BoundElsewhere { .. } => Ok(ui::error_page(
                    &app.templates,
                    base(app, Some(&login)),
                    StatusCode::CONFLICT,
                    "This agent belongs to someone else",
                    "This agent is already bound to another person on this server. That person \
                     must revoke it before it can act for you. The agent has been told the request \
                     was declined.",
                )),
                crate::consent::ApproveOutcome::Expired => Ok(ui::error_page(
                    &app.templates,
                    base(app, Some(&login)),
                    StatusCode::GONE,
                    "Too late",
                    "The agent's request (or its own credential) expired before your decision was \
                     recorded. Ask it to try again.",
                )),
            }
        }
        _ => Ok(page_err(
            app,
            Some(&login),
            ApiError::bad_request("invalid_request", "action must be approve or deny"),
        )),
    }
}

// ------------------------------------------------------------------ helpers

fn binding_value(b: crate::store::Binding) -> Value {
    context! {
        agent_iss => b.agent_iss, agent_sub => b.agent_sub, status => b.status,
        platform => b.platform, device => b.device, ap_name => b.ap_name,
        ap_logo_uri => b.ap_logo_uri, bound_at => b.bound_at, revoked_at => b.revoked_at,
    }
}

fn audit_value(a: crate::store::AuditRow) -> Value {
    context! { at => a.at, actor => a.actor, action => a.action, subject => a.subject }
}
