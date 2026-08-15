//! The human front door's plumbing: templates, HTML responses, cookies, forms.
//!
//! - **Templates** are `minijinja` (HTML auto-escaping on). The built-in set
//!   is embedded in the binary; a deployment may override any of them by file
//!   name via `ui.templates_dir` — an operator can restyle the consent screen
//!   without rebuilding, and a missing file falls back to the built-in.
//! - **No inline script or style**: pages load `/static/psd.css` and
//!   `/static/passkey.js` (also embedded), so every UI response carries a
//!   strict Content-Security-Policy. The consent screen itself needs no
//!   JavaScript at all; only the two passkey ceremonies do.
//! - **Sessions** are a random cookie value whose hash is stored; **CSRF**
//!   tokens are per-session and required on every state-changing UI POST
//!   (form field `csrf` or header `X-CSRF`).

use std::collections::HashMap;

use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use minijinja::{context, Environment, Value};

use crate::config::Config;
use crate::problem::{ApiError, Body, Resp};
use crate::reqctx::ReqCtx;

pub const SESSION_COOKIE: &str = "psd_session";

/// Built-in templates, by name. Overridable via `ui.templates_dir`.
const BUILTIN_TEMPLATES: &[(&str, &str)] = &[
    ("base.html", include_str!("../templates/base.html")),
    ("error.html", include_str!("../templates/error.html")),
    ("enrol.html", include_str!("../templates/enrol.html")),
    ("login.html", include_str!("../templates/login.html")),
    (
        "dashboard.html",
        include_str!("../templates/dashboard.html"),
    ),
    ("activity.html", include_str!("../templates/activity.html")),
    (
        "activity_rows.html",
        include_str!("../templates/activity_rows.html"),
    ),
    ("passkeys.html", include_str!("../templates/passkeys.html")),
    ("consent.html", include_str!("../templates/consent.html")),
    (
        "consent_code.html",
        include_str!("../templates/consent_code.html"),
    ),
    (
        "consent_done.html",
        include_str!("../templates/consent_done.html"),
    ),
];

const STATIC_CSS: &str = include_str!("../static/psd.css");
const STATIC_JS: &str = include_str!("../static/passkey.js");

const CSP: &str =
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' https:; \
                   form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

pub struct Templates {
    env: Environment<'static>,
    /// Names of templates loaded from the override directory (for logging).
    pub overridden: Vec<String>,
}

impl Templates {
    pub fn load(cfg: &Config) -> Result<Templates, String> {
        let mut env = Environment::new();
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
        env.add_filter("datetime", datetime_filter);
        // Percent-encode a value for use inside a URL query (the login page
        // carries `next` into the SSO start URL).
        env.add_filter("urlencode", |v: String| crate::oidc::form_encode(&v));
        let mut overridden = Vec::new();
        for (name, builtin) in BUILTIN_TEMPLATES {
            let source: String = match &cfg.ui.templates_dir {
                Some(dir) => {
                    let path = std::path::Path::new(dir).join(name);
                    if path.is_file() {
                        overridden.push(name.to_string());
                        std::fs::read_to_string(&path)
                            .map_err(|e| format!("cannot read template {}: {e}", path.display()))?
                    } else {
                        builtin.to_string()
                    }
                }
                None => builtin.to_string(),
            };
            env.add_template_owned(name.to_string(), source)
                .map_err(|e| format!("template {name} does not parse: {e}"))?;
        }
        Ok(Templates { env, overridden })
    }

    pub fn render(&self, name: &str, ctx: Value) -> Result<String, String> {
        let tpl = self
            .env
            .get_template(name)
            .map_err(|e| format!("template {name}: {e}"))?;
        tpl.render(ctx)
            .map_err(|e| format!("rendering {name}: {e}"))
    }
}

/// `{{ ts | datetime }}` — unix seconds → `YYYY-MM-DD HH:MM UTC`.
fn datetime_filter(v: Value) -> Value {
    match u64::try_from(v.clone()) {
        Ok(ts) => Value::from(format_utc(ts)),
        Err(_) => v,
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a unix time (mission blob timestamps).
pub fn iso8601(ts: u64) -> String {
    let (y, m, d) = civil_from_unix(ts);
    let secs = ts % 86400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Parse the `YYYY-MM-DDTHH:MM:SSZ` form back to unix seconds (blob round-trip).
#[cfg(test)]
pub fn parse_iso8601(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut dp = date.split('-');
    let (y, m, d): (i64, i64, i64) = (
        dp.next()?.parse().ok()?,
        dp.next()?.parse().ok()?,
        dp.next()?.parse().ok()?,
    );
    let mut tp = time.split(':');
    let (hh, mm, ss): (u64, u64, u64) = (
        tp.next()?.parse().ok()?,
        tp.next()?.parse().ok()?,
        tp.next()?.parse().ok()?,
    );
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // days from civil (Howard Hinnant)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86400 + hh * 3600 + mm * 60 + ss)
}

fn civil_from_unix(ts: u64) -> (i64, i64, i64) {
    let days = (ts / 86400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Civil date from unix time (Howard Hinnant's algorithm), no chrono needed.
pub fn format_utc(ts: u64) -> String {
    let (y, m, d) = civil_from_unix(ts);
    let secs = ts % 86400;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        secs / 3600,
        (secs % 3600) / 60
    )
}

// ------------------------------------------------------------------ responses

fn secure_headers(builder: hyper::http::response::Builder) -> hyper::http::response::Builder {
    builder
        .header("content-security-policy", CSP)
        .header("x-frame-options", "DENY")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .header("cache-control", "no-store")
}

pub fn html(status: StatusCode, body: String) -> Resp {
    secure_headers(Response::builder().status(status))
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::new(Bytes::from(body)))
        .unwrap()
}

/// `303 See Other` to a same-origin path.
pub fn redirect(location: &str) -> Resp {
    secure_headers(Response::builder().status(StatusCode::SEE_OTHER))
        .header("location", location)
        .body(Body::new(Bytes::new()))
        .unwrap()
}

/// Add a `Set-Cookie` header to a response.
pub fn with_cookie(mut resp: Resp, cookie: String) -> Resp {
    if let Ok(v) = hyper::header::HeaderValue::from_str(&cookie) {
        resp.headers_mut().append("set-cookie", v);
    }
    resp
}

/// The session cookie. `SameSite=Lax` (not Strict) because the person arrives
/// at the consent screen by a top-level navigation from another site — the
/// interaction URL an agent hands them — and Strict would drop the cookie on
/// exactly that hop. State-changing POSTs are protected by CSRF tokens.
/// `Secure` is omitted only when the issuer itself is plain http (dev mode).
pub fn session_cookie(cfg: &Config, value: &str, max_age: u64) -> String {
    let secure = if cfg.issuer.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!("{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}")
}

pub fn clear_session_cookie(cfg: &Config) -> String {
    session_cookie(cfg, "", 0)
}

pub fn static_asset(path: &str) -> Option<Resp> {
    let (body, ctype) = match path {
        "/static/psd.css" => (STATIC_CSS, "text/css; charset=utf-8"),
        "/static/passkey.js" => (STATIC_JS, "text/javascript; charset=utf-8"),
        _ => return None,
    };
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", ctype)
            .header("cache-control", "public, max-age=3600")
            .header("x-content-type-options", "nosniff")
            .body(Body::new(Bytes::from_static(body.as_bytes())))
            .unwrap(),
    )
}

// ------------------------------------------------------------- request parsing

/// The `psd_session` cookie value, if present.
pub fn session_id(ctx: &ReqCtx) -> Option<String> {
    for (name, value) in &ctx.headers {
        if name != "cookie" {
            continue;
        }
        for part in value.split(';') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Percent-decode a form component (`+` → space).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len()
                && s.is_char_boundary(i + 1)
                && s.is_char_boundary(i + 3) =>
            {
                let hex = &s[i + 1..i + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse an `application/x-www-form-urlencoded` body.
pub fn parse_form(body: &[u8]) -> HashMap<String, String> {
    let s = String::from_utf8_lossy(body);
    let mut out = HashMap::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(url_decode(k), url_decode(v));
    }
    out
}

/// A safe same-origin redirect target from user input: absolute path only.
pub fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.contains('\\') => n.to_string(),
        _ => "/".to_string(),
    }
}

/// The value of a query parameter, percent-decoded.
pub fn query_param(ctx: &ReqCtx, name: &str) -> Option<String> {
    let q = ctx.query.strip_prefix('?')?;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if url_decode(k) == name {
            return Some(url_decode(v));
        }
    }
    None
}

/// Constant-time equality for tokens.
pub fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// The CSRF token a UI POST presented: form field `csrf` or header `X-CSRF`.
pub fn presented_csrf(ctx: &ReqCtx, form: Option<&HashMap<String, String>>) -> Option<String> {
    if let Some(v) = ctx.header("x-csrf") {
        return Some(v);
    }
    form.and_then(|f| f.get("csrf").cloned())
}

// ------------------------------------------------------------ error rendering

/// An error page (HTML), for the human surface. Falls back to plain text if
/// the template itself is broken.
pub fn error_page(
    templates: &Templates,
    base: Value,
    status: StatusCode,
    title: &str,
    detail: &str,
) -> Resp {
    let ctx = context! { ..base, ..context! { title, detail } };
    match templates.render("error.html", ctx) {
        Ok(body) => html(status, body),
        Err(e) => secure_headers(Response::builder().status(status))
            .header("content-type", "text/plain; charset=utf-8")
            .body(Body::new(Bytes::from(format!(
                "{title}\n\n{detail}\n\n({e})"
            ))))
            .unwrap(),
    }
}

/// Convert an `ApiError` (problem+json) into an HTML error page for UI routes.
pub fn api_error_to_page(templates: &Templates, base: Value, err: ApiError) -> Resp {
    let title = match err.status {
        StatusCode::NOT_FOUND => "Not found",
        StatusCode::FORBIDDEN => "Not allowed",
        StatusCode::BAD_REQUEST => "Bad request",
        StatusCode::UNAUTHORIZED => "Sign in required",
        _ => "Something went wrong",
    };
    error_page(templates, base, err.status, title, &err.detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formatting() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_utc(1_786_806_834), "2026-08-15 15:13 UTC");
        assert_eq!(iso8601(1_786_806_834), "2026-08-15T15:13:54Z");
        assert_eq!(parse_iso8601("2026-08-15T15:13:54Z"), Some(1_786_806_834));
        assert_eq!(parse_iso8601("2026-04-07T14:30:00Z"), Some(1_775_572_200));
        for ts in [0u64, 951_782_400, 1_786_806_834, 4_102_444_800] {
            assert_eq!(parse_iso8601(&iso8601(ts)), Some(ts), "{ts}");
        }
        assert_eq!(parse_iso8601("garbage"), None);
    }

    #[test]
    fn form_and_query_parsing() {
        let f = parse_form(b"csrf=abc&agent_sub=aauth%3Aa%40ap.example&x=1+2");
        assert_eq!(f["csrf"], "abc");
        assert_eq!(f["agent_sub"], "aauth:a@ap.example");
        assert_eq!(f["x"], "1 2");
        let ctx = ReqCtx {
            method: "GET".into(),
            authority: "a".into(),
            path: "/login".into(),
            query: "?next=%2Fconsent%2Fabc&other=1".into(),
            headers: vec![
                ("cookie".into(), "foo=bar; psd_session=SID123; z=1".into()),
                ("x-csrf".into(), "H".into()),
            ],
            body: vec![],
        };
        assert_eq!(query_param(&ctx, "next").as_deref(), Some("/consent/abc"));
        assert_eq!(query_param(&ctx, "missing"), None);
        assert_eq!(session_id(&ctx).as_deref(), Some("SID123"));
        assert_eq!(presented_csrf(&ctx, None).as_deref(), Some("H"));
    }

    #[test]
    fn safe_next_only_accepts_absolute_paths() {
        assert_eq!(safe_next(Some("/consent/x")), "/consent/x");
        assert_eq!(safe_next(Some("//evil.example")), "/");
        assert_eq!(safe_next(Some("https://evil.example")), "/");
        assert_eq!(safe_next(Some("/a\\b")), "/");
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn templates_render_and_escape() {
        let cfg: Config =
            serde_json::from_value(serde_json::json!({ "issuer": "https://ps.example" })).unwrap();
        let t = Templates::load(&cfg).unwrap();
        assert!(t.overridden.is_empty());
        let body = t
            .render(
                "error.html",
                context! { ps_name => "PS", issuer => "https://ps.example", version => "0",
                person => Value::UNDEFINED, csrf => "",
                title => "T", detail => "<script>alert(1)</script>" },
            )
            .unwrap();
        // minijinja escapes `<`, `>` and `/`.
        assert!(
            body.contains("&lt;script&gt;alert(1)&lt;&#x2f;script&gt;"),
            "{body}"
        );
        assert!(!body.contains("<script>alert(1)"));
        assert!(body.contains("<title>T · PS</title>"));
    }

    #[test]
    fn template_override_dir() {
        let dir = std::env::temp_dir().join(format!("psd-tpl-{}", aauth_core::rand_id(8)));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("error.html"), "CUSTOM {{ title }}").unwrap();
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "issuer": "https://ps.example",
            "ui": { "templates_dir": dir.to_string_lossy() }
        }))
        .unwrap();
        cfg.validate().unwrap();
        let t = Templates::load(&cfg).unwrap();
        assert_eq!(t.overridden, vec!["error.html".to_string()]);
        let body = t.render("error.html", context! { title => "X" }).unwrap();
        assert_eq!(body, "CUSTOM X");
        // Others still built in.
        assert!(t.render("login.html", context! { ps_name => "P", next => "/", issuer => "i", version => "v", person => Value::UNDEFINED, csrf => "", passkeys_available => true }).unwrap().contains("passkey-get"));
        // A broken override is a startup error, not a runtime surprise.
        std::fs::write(dir.join("login.html"), "{% if %}").unwrap();
        assert!(Templates::load(&cfg).is_err());
    }

    #[test]
    fn cookie_attributes() {
        let https: Config =
            serde_json::from_value(serde_json::json!({ "issuer": "https://ps.example" })).unwrap();
        let c = session_cookie(&https, "v", 10);
        assert!(
            c.contains("HttpOnly") && c.contains("SameSite=Lax") && c.contains("; Secure"),
            "{c}"
        );
        let http: Config = serde_json::from_value(
            serde_json::json!({ "issuer": "http://localhost:8430", "insecure_dev_mode": true }),
        )
        .unwrap();
        assert!(!session_cookie(&http, "v", 10).contains("Secure"));
        assert!(clear_session_cookie(&https).contains("Max-Age=0"));
    }
}
