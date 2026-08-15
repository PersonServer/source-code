//! In-process tests. Handlers are driven through `router::dispatch` with a
//! hand-built `ReqCtx` (hyper bypassed for the server under test); the mock
//! Agent Provider runs a real hyper server on loopback so JWKS discovery and
//! egress admission are exercised for real. One test drives the real server
//! over a socket end to end.
//!
//! The mock AP is the sibling of `apd`'s test mocks: it serves
//! `/.well-known/aauth-agent.json` + `/.well-known/jwks.json` and mints agent
//! tokens with its own Ed25519 key.

use std::sync::Arc;

use aauth_core::jwk::Jwk;
use aauth_core::{jwt, sig, sigkey, tokens};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::app::App;
use crate::audit::Audit;
use crate::config::Config;
use crate::keys::KeySet;
use crate::problem::Resp;
use crate::reqctx::{self, ReqCtx};
use crate::router;

/// The dev-mode issuer of the PS under test and the `@authority` agents sign.
const PS_ISSUER: &str = "http://127.0.0.1:8430";
const PS_AUTHORITY: &str = "127.0.0.1:8430";

// ---------------------------------------------------------------- harness --

fn test_config(issuer: &str) -> Config {
    let cfg: Config = serde_json::from_value(serde_json::json!({
        "issuer": issuer,
        "listen": "127.0.0.1:0",
        "storage": { "backend": "sqlite", "path": ":memory:" },
        "insecure_dev_mode": true,
        "metadata": { "name": "Test PS" },
    }))
    .unwrap();
    cfg.validate().unwrap();
    cfg
}

fn build_app(cfg: Config) -> Arc<App> {
    let store = crate::store::Store::open(":memory:").unwrap();
    App::build(cfg, KeySet::generate(), Audit::quiet(), store).unwrap()
}

fn default_app() -> Arc<App> {
    build_app(test_config(PS_ISSUER))
}

async fn body_json(resp: Resp) -> (StatusCode, serde_json::Value, hyper::HeaderMap) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::String(
            String::from_utf8_lossy(&bytes).into_owned(),
        ))
    };
    (status, value, headers)
}

async fn call(
    app: &Arc<App>,
    method: Method,
    path: &str,
    ctx: ReqCtx,
) -> (StatusCode, serde_json::Value, hyper::HeaderMap) {
    match router::dispatch(&method, path, &ctx, app).await {
        Ok(resp) => body_json(resp).await,
        Err(e) => body_json(e.into_response()).await,
    }
}

fn hdr<'a>(headers: &'a hyper::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

// ---------------------------------------------------------------- mock AP --

/// A mock Agent Provider: metadata + JWKS on loopback, mints agent tokens.
struct MockAp {
    issuer: String,
    key: SigningKey,
    kid: String,
    _handle: tokio::task::JoinHandle<()>,
}

/// Knobs for misbehaving mock APs.
#[derive(Default, Clone)]
struct MockApOpts {
    /// Serve a metadata document claiming this issuer instead of the real one.
    claimed_issuer: Option<String>,
    /// Omit `issuer` from metadata entirely.
    omit_issuer: bool,
    /// Point `jwks_uri` at this host instead of the issuer host.
    jwks_host: Option<String>,
    /// Publish this key in the JWKS instead of the signing key.
    published_key: Option<SigningKey>,
}

async fn spawn_mock_ap(kid: &str, opts: MockApOpts) -> MockAp {
    // Dual-stack so a `localhost` jwks_uri (→ ::1) reaches the same server.
    let listener = TcpListener::bind("[::]:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let issuer = format!("http://127.0.0.1:{port}");
    let key = aauth_core::jwk::generate_signing_key();
    let published = opts.published_key.clone().unwrap_or_else(|| key.clone());
    let mut jwk = Jwk::from_verifying_key(&published.verifying_key());
    jwk.kid = Some(kid.to_string());
    jwk.use_ = Some("sig".into());
    let jwks_host = opts.jwks_host.clone().unwrap_or_else(|| "127.0.0.1".into());
    let mut meta = serde_json::json!({
        "jwks_uri": format!("http://{jwks_host}:{port}/.well-known/jwks.json"),
        "name": "Mock Agent Provider",
        "logo_uri": "https://ap.example/logo.png",
    });
    if !opts.omit_issuer {
        meta["issuer"] = serde_json::Value::String(
            opts.claimed_issuer
                .clone()
                .unwrap_or_else(|| issuer.clone()),
        );
    }
    let meta_s = meta.to_string();
    let jwks_s = serde_json::json!({ "keys": [jwk] }).to_string();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let meta_s = meta_s.clone();
            let jwks_s = jwks_s.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let meta_s = meta_s.clone();
                    let jwks_s = jwks_s.clone();
                    async move {
                        let (status, body) = match req.uri().path() {
                            "/.well-known/aauth-agent.json" => (200, meta_s),
                            "/.well-known/jwks.json" => (200, jwks_s),
                            _ => (404, "{}".to_string()),
                        };
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    MockAp {
        issuer,
        key,
        kid: kid.to_string(),
        _handle: handle,
    }
}

impl MockAp {
    /// Mint an agent token for `agent_local` bound to `agent_jwk`.
    fn mint(
        &self,
        agent_local: &str,
        agent_jwk: &Jwk,
        ttl: i64,
        extra: serde_json::Value,
    ) -> String {
        let now = aauth_core::now_unix() as i64;
        let domain = aauth_core::ident::host_of(&self.issuer).unwrap();
        let mut payload = serde_json::json!({
            "iss": self.issuer,
            "dwk": "aauth-agent.json",
            "sub": format!("aauth:{agent_local}@{domain}"),
            "jti": aauth_core::rand_token(96),
            "cnf": { "jwk": agent_jwk.public_only() },
            "iat": now,
            "exp": now + ttl,
        });
        if let Some(obj) = extra.as_object() {
            for (k, v) in obj {
                payload[k] = v.clone();
            }
        }
        jwt::sign(
            tokens::TYP_AGENT,
            Some(&self.kid),
            None,
            &payload,
            &self.key,
        )
    }
}

/// An agent: a signing key and its JWK.
struct Agent {
    key: SigningKey,
    jwk: Jwk,
}

fn new_agent() -> Agent {
    let key = aauth_core::jwk::generate_signing_key();
    let jwk = Jwk::from_verifying_key(&key.verifying_key());
    Agent { key, jwk }
}

// ---------------------------------------------------- signed request builder

struct AgentReq {
    method: Method,
    authority: String,
    path: String,
    body: Vec<u8>,
    /// Cover content-type + content-digest (the PS body rule). Default true
    /// when there is a body.
    cover_body: bool,
    /// Override the Content-Digest header value (tamper tests).
    digest_override: Option<String>,
    created: Option<u64>,
}

impl AgentReq {
    fn post(path: &str, body: serde_json::Value) -> AgentReq {
        AgentReq {
            method: Method::POST,
            authority: PS_AUTHORITY.into(),
            path: path.into(),
            body: body.to_string().into_bytes(),
            cover_body: true,
            digest_override: None,
            created: None,
        }
    }
    fn authority(mut self, a: &str) -> AgentReq {
        self.authority = a.into();
        self
    }
    fn created(mut self, c: u64) -> AgentReq {
        self.created = Some(c);
        self
    }
    fn no_body_coverage(mut self) -> AgentReq {
        self.cover_body = false;
        self
    }
    fn digest(mut self, d: &str) -> AgentReq {
        self.digest_override = Some(d.into());
        self
    }

    /// Sign with `signing` and present `sigkey_value` in `Signature-Key`.
    fn into_ctx(self, sigkey_value: &str, signing: &SigningKey) -> ReqCtx {
        let created = self.created.unwrap_or_else(aauth_core::now_unix);
        let digest = self
            .digest_override
            .clone()
            .unwrap_or_else(|| reqctx::content_digest_sha256(&self.body));
        let mut headers: Vec<(String, String)> = vec![("host".into(), self.authority.clone())];
        if !self.body.is_empty() {
            headers.push(("content-type".into(), "application/json".into()));
            headers.push(("content-digest".into(), digest));
        }
        let extra: Vec<&str> = if self.cover_body && !self.body.is_empty() {
            vec!["content-type", "content-digest"]
        } else {
            vec![]
        };
        let hdrs = headers.clone();
        let lookup = move |name: &str| hdrs.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
        let signed = sig::sign_request(
            self.method.as_str(),
            &self.authority,
            &self.path,
            "",
            &extra,
            &lookup,
            sigkey_value,
            signing,
            created,
        )
        .unwrap();
        headers.push(("signature-input".into(), signed.signature_input));
        headers.push(("signature".into(), signed.signature));
        headers.push(("signature-key".into(), signed.signature_key));
        ReqCtx {
            method: self.method.as_str().to_string(),
            authority: self.authority,
            path: self.path,
            query: String::new(),
            headers,
            body: self.body,
        }
    }
}

fn person_body() -> serde_json::Value {
    serde_json::json!({ "resource": "https://resource.example" })
}

/// A valid signed `/person` request from a fresh agent at `ap`.
fn signed_person(ap: &MockAp, agent: &Agent, ttl: i64) -> ReqCtx {
    let token = ap.mint("agent-1", &agent.jwk, ttl, serde_json::json!({}));
    AgentReq::post("/person", person_body()).into_ctx(&sigkey::serialize_jwt(&token), &agent.key)
}

// ------------------------------------------------------------ discovery docs

#[tokio::test]
async fn person_metadata_document() {
    let app = default_app();
    let (status, doc, headers) = body_json(crate::handlers::wellknown::person_metadata(&app)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hdr(&headers, "content-type"), Some("application/json"));
    assert!(hdr(&headers, "cache-control").unwrap().contains("max-age"));
    assert_eq!(doc["issuer"], PS_ISSUER);
    assert_eq!(
        doc["jwks_uri"],
        format!("{PS_ISSUER}/.well-known/jwks.json")
    );
    assert_eq!(doc["auth_token_endpoint"], format!("{PS_ISSUER}/token"));
    assert_eq!(doc["person_token_endpoint"], format!("{PS_ISSUER}/person"));
    assert_eq!(doc["accept_signature_algs"], serde_json::json!(["Ed25519"]));
    assert_eq!(doc["name"], "Test PS");
}

#[tokio::test]
async fn jwks_document_has_fully_specified_alg() {
    let app = default_app();
    let (status, doc, _) = body_json(crate::handlers::wellknown::jwks(&app)).await;
    assert_eq!(status, StatusCode::OK);
    let keys = doc["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["alg"], "Ed25519");
    assert_eq!(keys[0]["kty"], "OKP");
    assert_eq!(keys[0]["crv"], "Ed25519");
    assert_eq!(keys[0]["kid"], app.keys.active_kid);
    assert_eq!(keys[0]["use"], "sig");
    assert!(
        keys[0].get("d").is_none(),
        "JWKS must never carry private material"
    );
}

#[tokio::test]
async fn healthz() {
    let app = default_app();
    let (status, doc, _) = body_json(crate::handlers::wellknown::healthz(&app)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["status"], "ok");
    assert_eq!(doc["issuer"], PS_ISSUER);
}

#[tokio::test]
async fn unknown_route_is_problem_json_404() {
    let app = default_app();
    let ctx = ReqCtx {
        method: "GET".into(),
        authority: PS_AUTHORITY.into(),
        path: "/nope".into(),
        query: String::new(),
        headers: vec![],
        body: vec![],
    };
    let (status, body, headers) = call(&app, Method::GET, "/nope", ctx).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not_found");
    assert_eq!(
        hdr(&headers, "content-type"),
        Some("application/problem+json")
    );
}

// --------------------------------------------------- verification happy path

#[tokio::test]
async fn signed_person_request_from_new_agent_is_deferred() {
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let (status, body, headers) = call(
        &app,
        Method::POST,
        "/person",
        signed_person(&ap, &agent, 3600),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "pending");
    assert!(hdr(&headers, "signature-error").is_none());
    assert!(hdr(&headers, "location")
        .unwrap()
        .starts_with(&format!("{PS_ISSUER}/pending/pr-")));
    assert_eq!(hdr(&headers, "cache-control"), Some("no-store"));
    assert_eq!(hdr(&headers, "retry-after"), Some("5"));
    let req = hdr(&headers, "aauth-requirement").unwrap();
    assert!(req.starts_with("requirement=interaction; url=\""), "{req}");
    assert!(
        req.contains(&format!("url=\"{PS_ISSUER}/consent\"")),
        "{req}"
    );
    assert!(req.contains("; code=\""), "{req}");
}

#[tokio::test]
async fn signed_token_request_is_verified_then_validated() {
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let token = ap.mint("agent-1", &agent.jwk, 3600, serde_json::json!({}));
    let ctx = AgentReq::post("/token", serde_json::json!({ "resource_token": "x.y.z" }))
        .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
    let (status, body, _) = call(&app, Method::POST, "/token", ctx).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_resource_token");
    // and a verified request with a missing parameter is a 400 from the handler
    let ctx = AgentReq::post("/token", serde_json::json!({}))
        .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
    let (status, body, _) = call(&app, Method::POST, "/token", ctx).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn person_request_resource_validation_after_verification() {
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let token = ap.mint("agent-1", &agent.jwk, 3600, serde_json::json!({}));
    for bad in [
        serde_json::json!({}),
        serde_json::json!({ "resource": "resource.example" }),
        serde_json::json!({ "resource": "https://Resource.example" }),
        serde_json::json!({ "resource": "https://resource.example/" }),
        serde_json::json!({ "resource": 42 }),
    ] {
        let ctx = AgentReq::post("/person", bad.clone())
            .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
        let (status, body, _) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(body["error"], "invalid_request", "{bad}");
    }
}

#[tokio::test]
async fn jwks_is_cached_across_requests_and_kid_rotation_refreshes() {
    // Two requests from the same AP: the second must not need a fetch (the
    // floor would otherwise block it). Then an unknown kid → unknown_key.
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let (s1, b1, _) = call(
        &app,
        Method::POST,
        "/person",
        signed_person(&ap, &agent, 3600),
    )
    .await;
    assert_eq!(s1, StatusCode::ACCEPTED, "{b1}");
    let (s2, b2, _) = call(
        &app,
        Method::POST,
        "/person",
        signed_person(&ap, &agent, 3600),
    )
    .await;
    assert_eq!(s2, StatusCode::ACCEPTED, "{b2}");
    // A token naming a kid the JWKS does not have: refresh is rate-limited by
    // the floor (we just fetched), so unknown_key with the floor note.
    let payload_key = ap.key.clone();
    let now = aauth_core::now_unix() as i64;
    let domain = aauth_core::ident::host_of(&ap.issuer).unwrap();
    let token = jwt::sign(
        tokens::TYP_AGENT,
        Some("ap-key-rotated"),
        None,
        &serde_json::json!({
            "iss": ap.issuer, "dwk": "aauth-agent.json",
            "sub": format!("aauth:agent-1@{domain}"), "jti": "j",
            "cnf": { "jwk": agent.jwk.public_only() }, "iat": now, "exp": now + 600
        }),
        &payload_key,
    );
    let ctx = AgentReq::post("/person", person_body())
        .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(hdr(&headers, "signature-error"), Some("error=unknown_key"));
}

#[tokio::test]
async fn unreachable_agent_provider_is_503_not_unknown_key() {
    // The AP goes away between issuing the token and our first request for
    // it. We cannot verify — but that is *our* inability to consult the
    // issuer, not a verdict on the agent's key: 503 + Retry-After, no
    // Signature-Error, so the agent backs off instead of re-enrolling.
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let ctx = signed_person(&ap, &agent, 3600);
    ap._handle.abort();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("not a statement about your key"),
        "{body}"
    );
    assert!(
        hdr(&headers, "signature-error").is_none(),
        "no signature verdict"
    );
    let retry: u64 = hdr(&headers, "retry-after").unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry));
    // Within the fetch floor the answer is the same 503 (the failed attempt
    // consumed the minute), never unknown_key: we still have not seen a JWKS.
    let ctx = signed_person(&ap, &agent, 3600);
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], "temporarily_unavailable");
    let retry: u64 = hdr(&headers, "retry-after").unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry));
}

// ------------------------------------------------------- failure paths (401)

#[tokio::test]
async fn unsigned_request_is_401_invalid_request() {
    let app = default_app();
    let ctx = ReqCtx {
        method: "POST".into(),
        authority: PS_AUTHORITY.into(),
        path: "/person".into(),
        query: String::new(),
        headers: vec![("host".into(), PS_AUTHORITY.into())],
        body: person_body().to_string().into_bytes(),
    };
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(
        hdr(&headers, "signature-error"),
        Some("error=invalid_request")
    );
}

#[tokio::test]
async fn hwk_scheme_rejected_with_accept_signature_scheme() {
    let app = default_app();
    let agent = new_agent();
    let ctx = AgentReq::post("/person", person_body())
        .into_ctx(&sigkey::serialize_hwk(&agent.jwk), &agent.key);
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unsupported_scheme");
    assert_eq!(
        hdr(&headers, "signature-error"),
        Some("error=unsupported_scheme")
    );
    assert_eq!(hdr(&headers, "accept-signature-scheme"), Some("jwt"));
}

#[tokio::test]
async fn expired_agent_token_is_401_expired_jwt() {
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let (status, body, headers) = call(
        &app,
        Method::POST,
        "/person",
        signed_person(&ap, &agent, -5),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "expired_jwt");
    assert_eq!(hdr(&headers, "signature-error"), Some("error=expired_jwt"));
}

#[tokio::test]
async fn agent_token_with_bad_signature_is_401_invalid_jwt() {
    // The AP publishes key A but signs with key B.
    let other = aauth_core::jwk::generate_signing_key();
    let ap = spawn_mock_ap(
        "ap-key-1",
        MockApOpts {
            published_key: Some(other),
            ..Default::default()
        },
    )
    .await;
    let app = default_app();
    let agent = new_agent();
    let (status, body, headers) = call(
        &app,
        Method::POST,
        "/person",
        signed_person(&ap, &agent, 3600),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(hdr(&headers, "signature-error"), Some("error=invalid_jwt"));
}

#[tokio::test]
async fn non_agent_token_in_signature_key_is_rejected() {
    // A person-token-typed JWT presented where an agent token is required.
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let now = aauth_core::now_unix() as i64;
    let token = jwt::sign(
        tokens::TYP_PERSON,
        Some(&ap.kid),
        None,
        &serde_json::json!({
            "iss": ap.issuer, "dwk": "aauth-person.json", "sub": "x", "aud": "https://r.example",
            "cnf": { "jwk": agent.jwk.public_only() }, "jti": "j", "iat": now, "exp": now + 600
        }),
        &ap.key,
    );
    let ctx = AgentReq::post("/person", person_body())
        .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(hdr(&headers, "signature-error"), Some("error=invalid_jwt"));
    assert!(body["detail"].as_str().unwrap().contains("typ"));
}

#[tokio::test]
async fn metadata_issuer_mismatch_and_missing_are_rejected() {
    let ap = spawn_mock_ap(
        "ap-key-1",
        MockApOpts {
            claimed_issuer: Some("http://evil.example".into()),
            ..Default::default()
        },
    )
    .await;
    let app = default_app();
    let agent = new_agent();
    let (status, body, headers) = call(
        &app,
        Method::POST,
        "/person",
        signed_person(&ap, &agent, 3600),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        hdr(&headers, "signature-error"),
        Some("error=issuer_mismatch")
    );

    let ap = spawn_mock_ap(
        "ap-key-1",
        MockApOpts {
            omit_issuer: true,
            ..Default::default()
        },
    )
    .await;
    let (status, body, headers) = call(
        &app,
        Method::POST,
        "/person",
        signed_person(&ap, &agent, 3600),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        hdr(&headers, "signature-error"),
        Some("error=issuer_missing")
    );
}

#[tokio::test]
async fn cross_origin_jwks_uri_is_rejected() {
    // `localhost` and `127.0.0.1` are different hosts to the admission rule.
    let ap = spawn_mock_ap(
        "ap-key-1",
        MockApOpts {
            jwks_host: Some("localhost".into()),
            ..Default::default()
        },
    )
    .await;
    let app = default_app();
    let agent = new_agent();
    let (status, body, headers) = call(
        &app,
        Method::POST,
        "/person",
        signed_person(&ap, &agent, 3600),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(hdr(&headers, "signature-error"), Some("error=invalid_key"));
    assert!(body["detail"].as_str().unwrap().contains("cross-origin"));

    // …unless the deployment admits that host explicitly.
    let mut cfg = test_config(PS_ISSUER);
    cfg.jwks_cross_origin_hosts = vec!["localhost".into()];
    let app = build_app(cfg);
    let (status, body, _) = call(
        &app,
        Method::POST,
        "/person",
        signed_person(&ap, &agent, 3600),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
}

#[tokio::test]
async fn stale_created_is_401_invalid_signature() {
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let token = ap.mint("agent-1", &agent.jwk, 3600, serde_json::json!({}));
    let ctx = AgentReq::post("/person", person_body())
        .created(aauth_core::now_unix() - 600)
        .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        hdr(&headers, "signature-error"),
        Some("error=invalid_signature")
    );
}

#[tokio::test]
async fn body_request_must_cover_content_type_and_digest() {
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let token = ap.mint("agent-1", &agent.jwk, 3600, serde_json::json!({}));
    let ctx = AgentReq::post("/person", person_body())
        .no_body_coverage()
        .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_input");
    let se = hdr(&headers, "signature-error").unwrap();
    assert!(se.starts_with("error=invalid_input"), "{se}");
    assert!(se.contains("required_input="), "{se}");
    assert!(se.contains("\"content-digest\""), "{se}");
    assert!(se.contains("\"content-type\""), "{se}");
}

#[tokio::test]
async fn content_digest_mismatch_is_401() {
    // The header is covered and the signature is valid — but the header lies
    // about the body.
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let token = ap.mint("agent-1", &agent.jwk, 3600, serde_json::json!({}));
    let wrong = reqctx::content_digest_sha256(b"{\"resource\":\"https://other.example\"}");
    let ctx = AgentReq::post("/person", person_body())
        .digest(&wrong)
        .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        hdr(&headers, "signature-error"),
        Some("error=invalid_signature")
    );
    assert!(body["detail"].as_str().unwrap().contains("Content-Digest"));
}

#[tokio::test]
async fn http_signature_by_key_other_than_cnf_is_401() {
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let impostor = new_agent();
    let token = ap.mint("agent-1", &agent.jwk, 3600, serde_json::json!({}));
    let ctx = AgentReq::post("/person", person_body())
        .into_ctx(&sigkey::serialize_jwt(&token), &impostor.key);
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        hdr(&headers, "signature-error"),
        Some("error=invalid_signature")
    );
}

#[tokio::test]
async fn replayed_signature_is_rejected() {
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let token = ap.mint("agent-1", &agent.jwk, 3600, serde_json::json!({}));
    let created = aauth_core::now_unix();
    let mk = || {
        AgentReq::post("/person", person_body())
            .created(created)
            .into_ctx(&sigkey::serialize_jwt(&token), &agent.key)
    };
    let (s1, b1, _) = call(&app, Method::POST, "/person", mk()).await;
    assert_eq!(s1, StatusCode::ACCEPTED, "{b1}");
    let (s2, b2, headers) = call(&app, Method::POST, "/person", mk()).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED, "{b2}");
    assert_eq!(
        hdr(&headers, "signature-error"),
        Some("error=invalid_signature")
    );
    assert!(b2["detail"].as_str().unwrap().contains("replayed"));
}

// ------------------------------------------------------- failure paths (400)

#[tokio::test]
async fn wrong_authority_is_400_before_any_fetch() {
    // No mock AP at all: if verification tried discovery it would fail with a
    // 401 network error, so a 400 proves the authority check came first.
    let app = default_app();
    let agent = new_agent();
    let fake_token = jwt::sign(
        tokens::TYP_AGENT,
        Some("k"),
        None,
        &serde_json::json!({ "iss": "http://127.0.0.1:1", "dwk": "aauth-agent.json" }),
        &agent.key,
    );
    let ctx = AgentReq::post("/person", person_body())
        .authority("other.example")
        .into_ctx(&sigkey::serialize_jwt(&fake_token), &agent.key);
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
    assert!(hdr(&headers, "signature-error").is_none());
}

#[tokio::test]
async fn subagent_may_not_call_the_ps_directly() {
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let app = default_app();
    let agent = new_agent();
    let domain = aauth_core::ident::host_of(&ap.issuer).unwrap();
    let token = ap.mint(
        "planner+search1",
        &agent.jwk,
        3600,
        serde_json::json!({ "parent_agent": format!("aauth:planner@{domain}") }),
    );
    let ctx = AgentReq::post("/person", person_body())
        .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
    let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
    assert!(body["detail"].as_str().unwrap().contains("parent_agent"));
    assert!(hdr(&headers, "signature-error").is_none());
}

// ---------------------------------------------------- real server end to end

/// Minimal HTTP/1.1 client over a socket (hyper client conn) so the real
/// accept loop and `ReqCtx::read` are exercised.
async fn http_send(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value, hyper::HeaderMap) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut req = hyper::Request::builder().method(method).uri(path);
    for (n, v) in headers {
        req = req.header(n.as_str(), v.as_str());
    }
    let req = req
        .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let hdrs = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value, hdrs)
}

#[tokio::test]
async fn real_server_end_to_end() {
    let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // The issuer must name the port we actually got.
    let issuer = format!("http://127.0.0.1:{}", addr.port());
    let authority = format!("127.0.0.1:{}", addr.port());
    let app = build_app(test_config(&issuer));
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(crate::server::run(listener, app, async {
        let _ = rx.await;
    }));

    // Discovery documents over the wire.
    let (status, doc, _) =
        http_send(addr, "GET", "/.well-known/aauth-person.json", &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["issuer"], issuer);
    let (status, doc, _) = http_send(addr, "GET", "/.well-known/jwks.json", &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["keys"][0]["alg"], "Ed25519");
    let (status, doc, _) = http_send(addr, "GET", "/healthz", &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["status"], "ok");

    // A signed request built exactly as an agent would send it.
    let agent = new_agent();
    let token = ap.mint("agent-1", &agent.jwk, 3600, serde_json::json!({}));
    let ctx = AgentReq::post("/person", person_body())
        .authority(&authority)
        .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
    let (status, body, headers) =
        http_send(addr, "POST", "/person", &ctx.headers, ctx.body.clone()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert!(hdr(&headers, "signature-error").is_none());
    assert!(hdr(&headers, "aauth-requirement").is_some());

    // Tamper with the body on the wire → the covered digest no longer matches.
    let (status, body, headers) = http_send(
        addr,
        "POST",
        "/person",
        &ctx.headers,
        br#"{"resource":"https://evil.example"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        hdr(&headers, "signature-error"),
        Some("error=invalid_signature")
    );

    // Oversized body → 413 problem+json before any verification.
    let big = vec![b'x'; 70 * 1024];
    let (status, body, _) = http_send(
        addr,
        "POST",
        "/person",
        &[("host".into(), authority.clone())],
        big,
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["error"], "invalid_request");

    let _ = tx.send(());
    let _ = srv.await;
}

// --------------------------------------------------------- RFC test vectors

/// RFC 9421 Appendix B.2.6 — Ed25519 signature over the test request, using
/// `test-key-ed25519`. Confirms the signature-base construction we rely on
/// (via `aauth-core`) reproduces the RFC's bytes exactly, and that Ed25519
/// verification of the RFC's signature succeeds.
#[test]
fn rfc9421_b26_ed25519_vector() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // The RFC's request (§B.1): POST /foo?param=Value&Pet=dog, Host example.com
    let headers: Vec<(&str, &str)> = vec![
        ("host", "example.com"),
        ("date", "Tue, 20 Apr 2021 02:07:55 GMT"),
        ("content-type", "application/json"),
        (
            "content-digest",
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        ),
        ("content-length", "18"),
    ];
    let lookup = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.to_string())
    };
    let parts = sig::RequestParts {
        method: "POST",
        authority: "example.com",
        path: "/foo",
        query: "?param=Value&Pet=dog",
        header: &lookup,
    };
    let covered: Vec<String> = [
        "date",
        "@method",
        "@path",
        "@authority",
        "content-type",
        "content-length",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let params = r#"("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""#;
    let base = sig::build_signature_base(&covered, params, &parts).unwrap();
    let expected_base = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\
                         \"@method\": POST\n\
                         \"@path\": /foo\n\
                         \"@authority\": example.com\n\
                         \"content-type\": application/json\n\
                         \"content-length\": 18\n\
                         \"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";
    assert_eq!(base, expected_base);

    // test-key-ed25519 public key (SubjectPublicKeyInfo DER, RFC 9421 §B.1.4);
    // the raw key is the last 32 bytes.
    let spki =
        aauth_core::b64::decode_std("MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=")
            .unwrap();
    let raw: [u8; 32] = spki[spki.len() - 32..].try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&raw).unwrap();
    let sig_bytes = aauth_core::b64::decode_std(
        "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==",
    )
    .unwrap();
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
    vk.verify(base.as_bytes(), &signature)
        .expect("RFC 9421 B.2.6 signature must verify over the reconstructed base");
    // And the sha-512 Content-Digest of the RFC body is what the request carries.
    let mut ctx_headers = Vec::new();
    for (n, v) in &headers {
        ctx_headers.push((n.to_string(), v.to_string()));
    }
    let ctx = ReqCtx {
        method: "POST".into(),
        authority: "example.com".into(),
        path: "/foo".into(),
        query: "?param=Value&Pet=dog".into(),
        headers: ctx_headers,
        body: br#"{"hello": "world"}"#.to_vec(),
    };
    assert_eq!(
        ctx.header("content-digest").unwrap(),
        headers[3].1,
        "canonical header lookup"
    );
}

// ------------------------------------------------------------------ human UI

mod ui_tests {
    use super::*;
    use crate::passkey::fake_authenticator::FakeAuthenticator;
    use crate::ui;

    /// A hostname issuer: WebAuthn refuses IP-address RP IDs.
    pub(super) const UI_ISSUER: &str = "http://localhost:8430";
    pub(super) const UI_AUTHORITY: &str = "localhost:8430";

    pub(super) fn ui_app() -> Arc<App> {
        build_app(test_config(UI_ISSUER))
    }

    pub(super) fn get(path: &str, cookie: Option<&str>) -> ReqCtx {
        let (p, q) = path
            .split_once('?')
            .map(|(a, b)| (a, format!("?{b}")))
            .unwrap_or((path, String::new()));
        let mut headers = vec![("host".to_string(), UI_AUTHORITY.to_string())];
        if let Some(c) = cookie {
            headers.push(("cookie".into(), format!("{}={c}", ui::SESSION_COOKIE)));
        }
        ReqCtx {
            method: "GET".into(),
            authority: UI_AUTHORITY.into(),
            path: p.into(),
            query: q,
            headers,
            body: vec![],
        }
    }

    pub(super) fn post_json(
        path: &str,
        body: serde_json::Value,
        cookie: Option<&str>,
        csrf: Option<&str>,
    ) -> ReqCtx {
        let mut headers = vec![
            ("host".to_string(), UI_AUTHORITY.to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        if let Some(c) = cookie {
            headers.push(("cookie".into(), format!("{}={c}", ui::SESSION_COOKIE)));
        }
        if let Some(t) = csrf {
            headers.push(("x-csrf".into(), t.into()));
        }
        ReqCtx {
            method: "POST".into(),
            authority: UI_AUTHORITY.into(),
            path: path.into(),
            query: String::new(),
            headers,
            body: body.to_string().into_bytes(),
        }
    }

    pub(super) fn post_form(path: &str, fields: &[(&str, &str)], cookie: Option<&str>) -> ReqCtx {
        let mut headers = vec![
            ("host".to_string(), UI_AUTHORITY.to_string()),
            (
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
        ];
        if let Some(c) = cookie {
            headers.push(("cookie".into(), format!("{}={c}", ui::SESSION_COOKIE)));
        }
        let body = fields
            .iter()
            .map(|(k, v)| {
                format!(
                    "{k}={}",
                    v.replace(':', "%3A")
                        .replace('@', "%40")
                        .replace('/', "%2F")
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        ReqCtx {
            method: "POST".into(),
            authority: UI_AUTHORITY.into(),
            path: path.into(),
            query: String::new(),
            headers,
            body: body.into_bytes(),
        }
    }

    pub(super) async fn call_raw(
        app: &Arc<App>,
        method: Method,
        path: &str,
        ctx: ReqCtx,
    ) -> (StatusCode, String, hyper::HeaderMap) {
        let resp = match router::dispatch(&method, path.split('?').next().unwrap(), &ctx, app).await
        {
            Ok(r) => r,
            Err(e) => e.into_response(),
        };
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            String::from_utf8_lossy(&bytes).into_owned(),
            headers,
        )
    }

    pub(super) fn cookie_value(headers: &hyper::HeaderMap) -> Option<String> {
        let sc = headers.get("set-cookie")?.to_str().ok()?;
        let v = sc
            .split(';')
            .next()?
            .strip_prefix(&format!("{}=", ui::SESSION_COOKIE))?;
        Some(v.to_string())
    }

    /// Enrol a fresh person through the real routes; returns (person, session cookie, authenticator).
    pub(super) async fn enrol_person(
        app: &Arc<App>,
        name: &str,
    ) -> (crate::store::Person, String, FakeAuthenticator) {
        let person = app.store.create_person(name).unwrap();
        let token = app.store.create_enrolment(&person.id, 600).unwrap();
        let (status, body, headers) = call_raw(
            app,
            Method::GET,
            &format!("/enrol/{token}"),
            get(&format!("/enrol/{token}"), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("Create passkey"));
        assert!(body.contains(name));
        assert!(hdr(&headers, "content-security-policy")
            .unwrap()
            .contains("script-src 'self'"));
        assert_eq!(hdr(&headers, "x-frame-options"), Some("DENY"));
        let (status, options, _) = call(
            app,
            Method::POST,
            &format!("/enrol/{token}/options"),
            post_json(
                &format!("/enrol/{token}/options"),
                serde_json::json!({}),
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        assert_eq!(options["rp"]["id"], "localhost");
        let mut auth = FakeAuthenticator::new();
        let response = auth.create(&options, UI_ISSUER);
        let (status, body, headers) = call(
            app,
            Method::POST,
            &format!("/enrol/{token}/finish"),
            post_json(&format!("/enrol/{token}/finish"), response, None, None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["redirect"], "/");
        let sid = cookie_value(&headers).expect("session cookie");
        let sc = hdr(&headers, "set-cookie").unwrap();
        assert!(
            sc.contains("HttpOnly") && sc.contains("SameSite=Lax"),
            "{sc}"
        );
        assert!(!sc.contains("Secure"), "http issuer in dev mode: {sc}");
        (person, sid, auth)
    }

    #[tokio::test]
    async fn enrolment_registers_passkey_and_signs_in() {
        let app = ui_app();
        let (person, sid, _auth) = enrol_person(&app, "Alice Example").await;
        // The link is single-use.
        let creds = app.store.credentials_for_person(&person.id).unwrap();
        assert_eq!(creds.len(), 1);
        // Dashboard renders for the session.
        let (status, body, headers) = call_raw(&app, Method::GET, "/", get("/", Some(&sid))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("Alice Example"));
        assert!(body.contains("No agent has connected yet"));
        assert_eq!(hdr(&headers, "cache-control"), Some("no-store"));
        // Audit rows were written.
        let audit = app.store.recent_audit(Some(&person.id), 10).unwrap();
        assert!(audit.iter().any(|a| a.action == "passkey_registered"));
        assert!(audit.iter().any(|a| a.action == "signed_in"));
    }

    #[tokio::test]
    async fn enrolment_link_is_single_use_and_unknown_links_404() {
        let app = ui_app();
        let person = app.store.create_person("Bob").unwrap();
        let token = app.store.create_enrolment(&person.id, 600).unwrap();
        // Consume it.
        app.store.take_enrolment(&token).unwrap();
        let (status, body, _) = call_raw(
            &app,
            Method::GET,
            &format!("/enrol/{token}"),
            get(&format!("/enrol/{token}"), None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("not valid"));
        let (status, body, _) = call(
            &app,
            Method::POST,
            &format!("/enrol/{token}/options"),
            post_json(
                &format!("/enrol/{token}/options"),
                serde_json::json!({}),
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "invalid_enrolment");
        let (status, _, _) =
            call_raw(&app, Method::GET, "/enrol/nope", get("/enrol/nope", None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn login_with_passkey_and_logout() {
        let app = ui_app();
        let (person, _sid, mut auth) = enrol_person(&app, "Carol").await;
        // Fresh browser: dashboard redirects to login with next.
        let (status, _, headers) =
            call_raw(&app, Method::GET, "/activity", get("/activity", None)).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(hdr(&headers, "location"), Some("/login?next=/activity"));
        let (status, body, _) = call_raw(
            &app,
            Method::GET,
            "/login?next=/activity",
            get("/login?next=/activity", None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("passkey-get"));
        // minijinja escapes `/` in attributes; browsers decode it.
        assert!(
            body.contains(r#"data-next="/activity""#)
                || body.contains(r#"data-next="&#x2f;activity""#),
            "{body}"
        );
        // Ceremony.
        let (status, options, _) = call(
            &app,
            Method::POST,
            "/login/options",
            post_json("/login/options", serde_json::json!({}), None, None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        let assertion = auth.get(&options, UI_ISSUER, &person.user_handle);
        let (status, body, headers) = call(
            &app,
            Method::POST,
            "/login/finish",
            post_json(
                "/login/finish",
                serde_json::json!({ "credential": assertion, "next": "/activity" }),
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["redirect"], "/activity");
        let sid = cookie_value(&headers).unwrap();
        // Signed in.
        let (status, body, _) =
            call_raw(&app, Method::GET, "/activity", get("/activity", Some(&sid))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("signed_in"));
        // The sign counter advanced and was persisted.
        let cred = app.store.credential(&auth.cred_id).unwrap().unwrap();
        assert!(cred.last_used_at.is_some());
        // Open redirect attempts are neutralised.
        let assertion = auth.get(&options_again(&app).await, UI_ISSUER, &person.user_handle);
        let (_, body, _) = call(
            &app,
            Method::POST,
            "/login/finish",
            post_json(
                "/login/finish",
                serde_json::json!({ "credential": assertion, "next": "https://evil.example" }),
                None,
                None,
            ),
        )
        .await;
        assert_eq!(body["redirect"], "/");
        // Logout needs the CSRF token.
        let session = app.store.get_session(&sid).unwrap().unwrap();
        let (status, body, _) = call_raw(
            &app,
            Method::POST,
            "/logout",
            post_form("/logout", &[("csrf", "wrong")], Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, _, headers) = call_raw(
            &app,
            Method::POST,
            "/logout",
            post_form("/logout", &[("csrf", &session.csrf)], Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(hdr(&headers, "set-cookie").unwrap().contains("Max-Age=0"));
        let (status, _, _) = call_raw(&app, Method::GET, "/", get("/", Some(&sid))).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "session gone");
    }

    async fn options_again(app: &Arc<App>) -> serde_json::Value {
        let (_, options, _) = call(
            app,
            Method::POST,
            "/login/options",
            post_json("/login/options", serde_json::json!({}), None, None),
        )
        .await;
        options
    }

    #[tokio::test]
    async fn login_rejects_foreign_credentials() {
        let app = ui_app();
        let (person, _sid, _auth) = enrol_person(&app, "Dave").await;
        // An authenticator that was never registered.
        let mut stranger = FakeAuthenticator::new();
        let (_, options, _) = call(
            &app,
            Method::POST,
            "/login/options",
            post_json("/login/options", serde_json::json!({}), None, None),
        )
        .await;
        let assertion = stranger.get(&options, UI_ISSUER, &person.user_handle);
        let (status, body, headers) = call(
            &app,
            Method::POST,
            "/login/finish",
            post_json(
                "/login/finish",
                serde_json::json!({ "credential": assertion }),
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"], "authentication_failed");
        assert!(hdr(&headers, "set-cookie").is_none());
        // Missing credential member.
        let (status, _, _) = call(
            &app,
            Method::POST,
            "/login/finish",
            post_json("/login/finish", serde_json::json!({}), None, None),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn dashboard_lists_and_revokes_bindings_with_csrf() {
        let app = ui_app();
        let (alice, sid, _auth) = enrol_person(&app, "Alice").await;
        let (bob, bob_sid, _auth2) = enrol_person(&app, "Bob").await;
        app.store
            .bind_agent(
                "https://ap.example",
                "aauth:helper@ap.example",
                &alice.id,
                &crate::store::BindingDisplay {
                    platform: Some("server".into()),
                    device: Some("Alice's laptop".into()),
                    ap_name: Some("Example AP".into()),
                    ap_logo_uri: None,
                },
            )
            .unwrap()
            .unwrap();
        let (status, body, _) = call_raw(&app, Method::GET, "/", get("/", Some(&sid))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("aauth:helper@ap.example"));
        assert!(body.contains("Example AP"));
        assert!(
            body.contains("Alice&#x27;s laptop") || body.contains("Alice's laptop"),
            "device shown (escaped)"
        );
        assert!(body.contains("unverified"));
        // Bob sees nothing of Alice's, and cannot revoke her agent.
        let (_, body, _) = call_raw(&app, Method::GET, "/", get("/", Some(&bob_sid))).await;
        assert!(!body.contains("aauth:helper@ap.example"));
        let bob_csrf = app.store.get_session(&bob_sid).unwrap().unwrap().csrf;
        let (status, _, _) = call_raw(
            &app,
            Method::POST,
            "/agents/revoke",
            post_form(
                "/agents/revoke",
                &[
                    ("csrf", &bob_csrf),
                    ("agent_iss", "https://ap.example"),
                    ("agent_sub", "aauth:helper@ap.example"),
                ],
                Some(&bob_sid),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(app
            .store
            .binding("https://ap.example", "aauth:helper@ap.example")
            .unwrap()
            .unwrap()
            .is_active());
        let _ = bob;
        // Alice without CSRF → 403 and still active.
        let (status, _, _) = call_raw(
            &app,
            Method::POST,
            "/agents/revoke",
            post_form(
                "/agents/revoke",
                &[
                    ("agent_iss", "https://ap.example"),
                    ("agent_sub", "aauth:helper@ap.example"),
                ],
                Some(&sid),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(app
            .store
            .binding("https://ap.example", "aauth:helper@ap.example")
            .unwrap()
            .unwrap()
            .is_active());
        // Alice with CSRF → revoked, audited, dashboard shows it.
        let csrf = app.store.get_session(&sid).unwrap().unwrap().csrf;
        let (status, _, headers) = call_raw(
            &app,
            Method::POST,
            "/agents/revoke",
            post_form(
                "/agents/revoke",
                &[
                    ("csrf", &csrf),
                    ("agent_iss", "https://ap.example"),
                    ("agent_sub", "aauth:helper@ap.example"),
                ],
                Some(&sid),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(hdr(&headers, "location"), Some("/"));
        assert!(!app
            .store
            .binding("https://ap.example", "aauth:helper@ap.example")
            .unwrap()
            .unwrap()
            .is_active());
        let (_, body, _) = call_raw(&app, Method::GET, "/", get("/", Some(&sid))).await;
        assert!(body.contains("revoked"));
        assert!(app
            .store
            .recent_audit(Some(&alice.id), 10)
            .unwrap()
            .iter()
            .any(|a| a.action == "binding_revoked"));
    }

    #[tokio::test]
    async fn add_second_passkey_requires_session_and_csrf() {
        let app = ui_app();
        let (person, sid, _auth) = enrol_person(&app, "Eve").await;
        let csrf = app.store.get_session(&sid).unwrap().unwrap().csrf;
        // No session → 401 problem on the JSON route.
        let (status, _, _) = call(
            &app,
            Method::POST,
            "/passkeys/options",
            post_json("/passkeys/options", serde_json::json!({}), None, None),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Session but no CSRF → 403.
        let (status, _, _) = call(
            &app,
            Method::POST,
            "/passkeys/options",
            post_json("/passkeys/options", serde_json::json!({}), Some(&sid), None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // Proper.
        let (status, options, _) = call(
            &app,
            Method::POST,
            "/passkeys/options",
            post_json(
                "/passkeys/options",
                serde_json::json!({}),
                Some(&sid),
                Some(&csrf),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        assert_eq!(
            options["excludeCredentials"].as_array().unwrap().len(),
            1,
            "existing passkey excluded"
        );
        let mut second = FakeAuthenticator::new();
        let response = second.create(&options, UI_ISSUER);
        let (status, body, _) = call(
            &app,
            Method::POST,
            "/passkeys/finish",
            post_json("/passkeys/finish", response, Some(&sid), Some(&csrf)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            app.store.credentials_for_person(&person.id).unwrap().len(),
            2
        );
        let (status, body, _) =
            call_raw(&app, Method::GET, "/passkeys", get("/passkeys", Some(&sid))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.matches("<tr>").count(), 3, "header row + two passkeys");
        let (status, body, _) = call_raw(
            &app,
            Method::GET,
            "/passkeys/add",
            get("/passkeys/add", Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Add a passkey"));
    }

    #[tokio::test]
    async fn ip_issuer_has_no_passkeys_but_explains() {
        // The agent-facing tests use http://127.0.0.1:8430; the UI must not
        // panic there, just explain.
        let app = default_app();
        assert!(app.passkeys.is_none());
        let person = app.store.create_person("Zed").unwrap();
        let token = app.store.create_enrolment(&person.id, 600).unwrap();
        let ctx = ReqCtx {
            method: "GET".into(),
            authority: PS_AUTHORITY.into(),
            path: format!("/enrol/{token}"),
            query: String::new(),
            headers: vec![],
            body: vec![],
        };
        let (status, body, _) = call_raw(&app, Method::GET, &format!("/enrol/{token}"), ctx).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("hostname"), "{body}");
    }

    #[test]
    fn static_assets_are_served() {
        let css = ui::static_asset("/static/psd.css").unwrap();
        assert_eq!(
            css.headers().get("content-type").unwrap(),
            "text/css; charset=utf-8"
        );
        let js = ui::static_asset("/static/passkey.js").unwrap();
        assert_eq!(
            js.headers().get("content-type").unwrap(),
            "text/javascript; charset=utf-8"
        );
        assert!(ui::static_asset("/static/../Cargo.toml").is_none());
        assert!(ui::static_asset("/static/other.js").is_none());
    }
}

// ------------------------------------------- person tokens, consent, polling

/// Helpers shared by the flow tests.
mod flow_support {
    pub(super) use super::person_token_tests::{
        agent_req, decide, pending_and_code, poll, post_person,
    };
}

mod person_token_tests {
    use super::ui_tests::{
        call_raw, enrol_person, get, post_form, ui_app, UI_AUTHORITY, UI_ISSUER,
    };
    use super::*;

    /// A signed agent request against the UI-capable app (hostname issuer).
    pub(super) fn agent_req(
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
        ap: &MockAp,
        agent: &Agent,
        local: &str,
        extra_claims: serde_json::Value,
    ) -> ReqCtx {
        let token = ap.mint(local, &agent.jwk, 3600, extra_claims);
        let mut req = match body {
            Some(b) => AgentReq::post(path, b),
            None => AgentReq {
                method: Method::GET,
                authority: UI_AUTHORITY.into(),
                path: path.into(),
                body: vec![],
                cover_body: false,
                digest_override: None,
                created: None,
            },
        };
        req.method = method;
        req = req.authority(UI_AUTHORITY);
        req.into_ctx(&sigkey::serialize_jwt(&token), &agent.key)
    }

    fn with_prefer(mut ctx: ReqCtx, wait: u64) -> ReqCtx {
        ctx.headers.push(("prefer".into(), format!("wait={wait}")));
        ctx
    }

    /// POST /person for `resource`; returns (status, body, headers).
    pub(super) async fn post_person(
        app: &Arc<App>,
        ap: &MockAp,
        agent: &Agent,
        local: &str,
        resource: &str,
    ) -> (StatusCode, serde_json::Value, hyper::HeaderMap) {
        let ctx = agent_req(
            Method::POST,
            "/person",
            Some(
                serde_json::json!({ "resource": resource, "platform": "server", "device": "CI box" }),
            ),
            ap,
            agent,
            local,
            serde_json::json!({}),
        );
        call(app, Method::POST, "/person", ctx).await
    }

    pub(super) async fn poll(
        app: &Arc<App>,
        ap: &MockAp,
        agent: &Agent,
        local: &str,
        pending_id: &str,
    ) -> (StatusCode, serde_json::Value, hyper::HeaderMap) {
        let path = format!("/pending/{pending_id}");
        let ctx = agent_req(
            Method::GET,
            &path,
            None,
            ap,
            agent,
            local,
            serde_json::json!({}),
        );
        call(app, Method::GET, &path, ctx).await
    }

    /// Parse `Location` → pending id and `AAuth-Requirement` → code.
    pub(super) fn pending_and_code(headers: &hyper::HeaderMap) -> (String, String) {
        let loc = hdr(headers, "location").unwrap();
        let id = loc.rsplit('/').next().unwrap().to_string();
        let req = hdr(headers, "aauth-requirement").unwrap();
        let code = req
            .split("code=\"")
            .nth(1)
            .unwrap()
            .trim_end_matches('"')
            .to_string();
        (id, code)
    }

    /// The person opens the consent link with the code and decides.
    pub(super) async fn decide(
        app: &Arc<App>,
        sid: &str,
        code: &str,
        action: &str,
    ) -> (StatusCode, String) {
        let (status, _, headers) = call_raw(
            app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code}"), Some(sid)),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "code should resolve");
        let loc = hdr(&headers, "location").unwrap().to_string();
        let (status, page, _) = call_raw(app, Method::GET, &loc, get(&loc, Some(sid))).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let csrf = app.store.get_session(sid).unwrap().unwrap().csrf;
        call_raw(
            app,
            Method::POST,
            &loc,
            post_form(&loc, &[("csrf", &csrf), ("action", action)], Some(sid)),
        )
        .await
        .into_2()
    }

    /// How minijinja's HTML autoescape renders a URL-ish string in text.
    fn esc(s: &str) -> String {
        s.replace('/', "&#x2f;")
    }

    trait Into2 {
        fn into_2(self) -> (StatusCode, String);
    }
    impl Into2 for (StatusCode, String, hyper::HeaderMap) {
        fn into_2(self) -> (StatusCode, String) {
            (self.0, self.1)
        }
    }

    fn verify_person_token(app: &Arc<App>, token: &str) -> serde_json::Value {
        let decoded = jwt::decode(token).unwrap();
        assert_eq!(decoded.header.typ.as_deref(), Some(tokens::TYP_PERSON));
        assert_eq!(decoded.header.alg, "Ed25519");
        let kid = decoded.header.kid.as_deref().unwrap();
        assert_eq!(kid, app.keys.active_kid);
        let key = app.keys.find_public(kid).unwrap();
        jwt::verify_with_jwk(&decoded, key).expect("signature by our active key");
        decoded.payload
    }

    #[tokio::test]
    async fn person_token_end_to_end() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let app = ui_app();
        let agent = new_agent();
        let (alice, sid, _auth) = enrol_person(&app, "Alice").await;

        // 1. A new agent asks: 202 with the interaction requirement.
        let (status, body, headers) =
            post_person(&app, &ap, &agent, "helper", "https://resource.example").await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["status"], "pending");
        let (pid, code) = pending_and_code(&headers);
        assert!(pid.starts_with("pr-"));
        assert_eq!(code.len(), 9);
        assert!(hdr(&headers, "aauth-requirement")
            .unwrap()
            .contains(&format!("url=\"{UI_ISSUER}/consent\"")));

        // 2. Polling: same agent sees pending (with the requirement again);
        //    another agent sees 404; unsigned is 401.
        let (status, body, headers) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert!(hdr(&headers, "aauth-requirement").is_some());
        let other = new_agent();
        let (status, body, _) = poll(&app, &ap, &other, "someone-else", &pid).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        let bare = ReqCtx {
            method: "GET".into(),
            authority: UI_AUTHORITY.into(),
            path: format!("/pending/{pid}"),
            query: String::new(),
            headers: vec![("host".into(), UI_AUTHORITY.into())],
            body: vec![],
        };
        let (status, _, _) = call(&app, Method::GET, &format!("/pending/{pid}"), bare).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // 3. The dashboard does not list an unclaimed request; the person
        //    arrives with the code, sees the screen, allows.
        let (_, dash, _) = call_raw(&app, Method::GET, "/", get("/", Some(&sid))).await;
        assert!(!dash.contains("Waiting for your decision"));
        let (status, _, headers) = call_raw(
            &app,
            Method::GET,
            "/consent",
            get(
                &format!("/consent?code={}", code.to_lowercase()),
                Some(&sid),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            hdr(&headers, "location"),
            Some(format!("/consent/{pid}").as_str())
        );
        // now claimed: the poll shows interacting, without the requirement
        let (status, body, headers) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "interacting");
        assert!(hdr(&headers, "aauth-requirement").is_none());
        // and the dashboard lists it
        let (_, dash, _) = call_raw(&app, Method::GET, "/", get("/", Some(&sid))).await;
        assert!(dash.contains("Waiting for your decision"));
        assert!(dash.contains(&esc("https://resource.example")));
        // the code is single-use
        let (status, page, _) = call_raw(
            &app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code}"), Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("not recognised"));

        let path = format!("/consent/{pid}");
        let (status, page, _) = call_raw(&app, Method::GET, &path, get(&path, Some(&sid))).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.contains("new agent"), "new-agent banner");
        assert!(page.contains("aauth:helper@"));
        assert!(
            page.contains("Mock Agent Provider"),
            "AP name from metadata"
        );
        assert!(
            page.contains(&esc("https://ap.example/logo.png")),
            "AP logo"
        );
        assert!(page.contains("CI box") && page.contains("unverified"));
        assert!(page.contains("resource.example"));
        assert!(
            page.contains("publishes no description"),
            "resource has no metadata"
        );
        assert!(page.contains("act at"));
        // approve without CSRF fails and changes nothing
        let (status, _, _) = call_raw(
            &app,
            Method::POST,
            &path,
            post_form(&path, &[("action", "approve")], Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(app.store.pending(&pid).unwrap().unwrap().is_open());
        let csrf = app.store.get_session(&sid).unwrap().unwrap().csrf;
        let (status, page, _) = call_raw(
            &app,
            Method::POST,
            &path,
            post_form(&path, &[("csrf", &csrf), ("action", "approve")], Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.contains("Allowed"));

        // 4. The agent polls and gets the token, once.
        let (status, body, headers) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(hdr(&headers, "cache-control"), Some("no-store"));
        let token = body["person_token"].as_str().unwrap().to_string();
        let expires_in = body["expires_in"].as_u64().unwrap();
        assert!(expires_in > 3500 && expires_in <= 3600, "{expires_in}");
        let claims = verify_person_token(&app, &token);
        assert_eq!(claims["iss"], UI_ISSUER);
        assert_eq!(claims["dwk"], "aauth-person.json");
        assert_eq!(claims["aud"], "https://resource.example");
        assert_eq!(
            claims["cnf"]["jwk"],
            serde_json::to_value(agent.jwk.public_only()).unwrap()
        );
        assert_eq!(claims["cnf"]["jwk"]["alg"], "Ed25519");
        let sub = claims["sub"].as_str().unwrap().to_string();
        assert!(!sub.is_empty());
        let jti = claims["jti"].as_str().unwrap().to_string();
        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();
        assert!(exp - iat <= 3600, "lifetime ≤ 1h");
        assert!(claims.get("scope").is_none() && claims.get("account").is_none());
        assert!(claims.get("mission_s256").is_none());
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::GONE, "{body}");

        // 5. Retention, binding, consent, directed sub.
        let rec = app
            .store
            .person_token_record(&jti)
            .unwrap()
            .expect("retained");
        assert_eq!(rec.ps, UI_ISSUER);
        assert_eq!(rec.sub, sub);
        assert_eq!(rec.aud, "https://resource.example");
        assert_eq!(rec.exp, exp);
        assert_eq!(rec.purge_after, exp + app.cfg.retention_secs());
        assert_eq!(rec.person_id, alice.id);
        assert!(rec.agent_sub.starts_with("aauth:helper@"));
        assert_eq!(rec.mission_s256, None);
        let binding = app
            .store
            .binding(&ap.issuer, &rec.agent_sub)
            .unwrap()
            .unwrap();
        assert!(binding.is_active());
        assert_eq!(binding.person_id, alice.id);
        assert_eq!(binding.ap_name.as_deref(), Some("Mock Agent Provider"));
        assert_eq!(binding.platform.as_deref(), Some("server"));
        assert!(app
            .store
            .find_consent(
                &alice.id,
                &ap.issuer,
                &rec.agent_sub,
                "https://resource.example",
                "person"
            )
            .unwrap()
            .is_some());
        assert_eq!(
            app.keys.derive_sub(&alice.id, "https://resource.example"),
            sub
        );
        let (_, dash, _) = call_raw(&app, Method::GET, "/", get("/", Some(&sid))).await;
        assert!(dash.contains("aauth:helper@") && dash.contains("Mock Agent Provider"));
        assert!(dash.contains("person_token_issued"));

        // 6. Consent on record: the same request now answers 200 directly,
        //    with the same directed sub; a new resource defers again.
        let (status, body, _) =
            post_person(&app, &ap, &agent, "helper", "https://resource.example").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let claims = verify_person_token(&app, body["person_token"].as_str().unwrap());
        assert_eq!(claims["sub"], sub, "sub MUST NOT vary between issuances");
        assert_ne!(claims["jti"], jti);
        let (status, _, headers) =
            post_person(&app, &ap, &agent, "helper", "https://other.example").await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (pid2, code2) = pending_and_code(&headers);
        // this one is pre-claimed for Alice (bound agent) — visible on her dashboard
        assert_eq!(
            app.store
                .pending(&pid2)
                .unwrap()
                .unwrap()
                .person_id
                .as_deref(),
            Some(alice.id.as_str())
        );
        let (_, dash, _) = call_raw(&app, Method::GET, "/", get("/", Some(&sid))).await;
        assert!(dash.contains(&esc("https://other.example")));
        let (status, page) = decide(&app, &sid, &code2, "approve").await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid2).await;
        assert_eq!(status, StatusCode::OK);
        let claims = verify_person_token(&app, body["person_token"].as_str().unwrap());
        assert_ne!(
            claims["sub"], sub,
            "pairwise: a different resource sees a different sub"
        );

        // 7. Revoking the binding on the dashboard also revokes consent: the
        //    next request defers again.
        let (status, _, _) = call_raw(
            &app,
            Method::POST,
            "/agents/revoke",
            post_form(
                "/agents/revoke",
                &[
                    ("csrf", &csrf),
                    ("agent_iss", &ap.issuer),
                    ("agent_sub", &rec.agent_sub),
                ],
                Some(&sid),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let (status, _, _) =
            post_person(&app, &ap, &agent, "helper", "https://resource.example").await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "revoked binding: consent again"
        );
    }

    #[tokio::test]
    async fn deny_and_expiry_and_gone() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let app = ui_app();
        let agent = new_agent();
        let (_alice, sid, _auth) = enrol_person(&app, "Alice").await;
        let (status, _, headers) =
            post_person(&app, &ap, &agent, "helper", "https://resource.example").await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (pid, code) = pending_and_code(&headers);
        let (status, page) = decide(&app, &sid, &code, "deny").await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.contains("Not allowed"));
        let (status, body, headers) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "denied");
        assert!(
            hdr(&headers, "signature-error").is_none(),
            "403 never negotiates"
        );
        assert!(
            app.store
                .binding(
                    &ap.issuer,
                    &format!(
                        "aauth:helper@{}",
                        aauth_core::ident::host_of(&ap.issuer).unwrap()
                    )
                )
                .unwrap()
                .is_none(),
            "no binding on deny"
        );

        // Expiry: a pending row past its deadline answers 408.
        let domain = aauth_core::ident::host_of(&ap.issuer).unwrap();
        let pr = app
            .store
            .create_pending(
                "person",
                &ap.issuer,
                &format!("aauth:helper@{domain}"),
                None,
                &serde_json::json!({ "resource": "https://r.example", "code": "AAAA-AAAA" }),
                "somehash",
                0,
            )
            .unwrap();
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pr.id).await;
        assert_eq!(status, StatusCode::REQUEST_TIMEOUT, "{body}");
        assert_eq!(body["error"], "expired");
        // The consent page for an expired request says so.
        app.store.claim_pending(&pr.id, "x").unwrap();
        let path = format!("/consent/{}", pr.id);
        let (status, _, _) = call_raw(&app, Method::GET, &path, get(&path, Some(&sid))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "expired + not mine → 404");
    }

    #[tokio::test]
    async fn code_attempts_are_limited_and_unclaimed_id_needs_code() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let mut cfg = test_config(UI_ISSUER);
        cfg.limits.code_attempts = 2;
        let app = build_app(cfg);
        let agent = new_agent();
        let (_alice, sid, _auth) = enrol_person(&app, "Alice").await;
        let (_, _, headers) =
            post_person(&app, &ap, &agent, "helper", "https://resource.example").await;
        let (pid, code) = pending_and_code(&headers);
        // Direct id without a claim redirects to the code page.
        let path = format!("/consent/{pid}");
        let (status, _, headers) = call_raw(&app, Method::GET, &path, get(&path, Some(&sid))).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(hdr(&headers, "location"), Some("/consent"));
        // Two wrong codes, then locked out even for the right one.
        for _ in 0..2 {
            let (status, page, _) = call_raw(
                &app,
                Method::GET,
                "/consent",
                get("/consent?code=ZZZZ-ZZZZ", Some(&sid)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(page.contains("not recognised"));
        }
        let (status, page, _) = call_raw(
            &app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code}"), Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{page}");
        // The bare code page renders (no code given).
        let (status, page, _) =
            call_raw(&app, Method::GET, "/consent", get("/consent", Some(&sid))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("Enter the code"));
        // Not logged in → redirected to login carrying the code.
        let (status, _, headers) = call_raw(
            &app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code}"), None),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(hdr(&headers, "location")
            .unwrap()
            .starts_with("/login?next=/consent"));
    }

    #[tokio::test]
    async fn agent_bound_to_another_person_cannot_be_claimed_or_approved() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let app = ui_app();
        let agent = new_agent();
        let (alice, alice_sid, _a) = enrol_person(&app, "Alice").await;
        let (_bob, bob_sid, _b) = enrol_person(&app, "Bob").await;
        // Alice binds the agent.
        let (_, _, headers) = post_person(&app, &ap, &agent, "helper", "https://r1.example").await;
        let (pid, code) = pending_and_code(&headers);
        let (status, _) = decide(&app, &alice_sid, &code, "approve").await;
        assert_eq!(status, StatusCode::OK);
        let _ = poll(&app, &ap, &agent, "helper", &pid).await;
        // A new resource: the pending is pre-claimed for Alice; Bob's code
        // presentation is refused (409) and does not consume anything.
        let (_, _, headers) = post_person(&app, &ap, &agent, "helper", "https://r2.example").await;
        let (pid2, code2) = pending_and_code(&headers);
        let (status, page, _) = call_raw(
            &app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code2}"), Some(&bob_sid)),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{page}");
        assert!(app.store.pending(&pid2).unwrap().unwrap().is_open());
        // Alice can still decide it.
        let (status, _) = decide(&app, &alice_sid, &code2, "approve").await;
        assert_eq!(status, StatusCode::OK);
        // Bob's own agent, same `sub` string at a *different* AP, is his.
        let ap2 = spawn_mock_ap("ap2-key", MockApOpts::default()).await;
        let (_, _, headers) = post_person(&app, &ap2, &agent, "helper", "https://r1.example").await;
        let (pid3, code3) = pending_and_code(&headers);
        let (status, _) = decide(&app, &bob_sid, &code3, "approve").await;
        assert_eq!(status, StatusCode::OK);
        let (status, body, _) = poll(&app, &ap2, &agent, "helper", &pid3).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let claims = verify_person_token(&app, body["person_token"].as_str().unwrap());
        // Same audience, different person → different directed sub than Alice's.
        assert_ne!(
            claims["sub"],
            app.keys.derive_sub(&alice.id, "https://r1.example")
        );
        // Revoked binding can be re-claimed by Bob later.
        let csrf = app.store.get_session(&alice_sid).unwrap().unwrap().csrf;
        let helper_sub = format!(
            "aauth:helper@{}",
            aauth_core::ident::host_of(&ap.issuer).unwrap()
        );
        let (status, _, _) = call_raw(
            &app,
            Method::POST,
            "/agents/revoke",
            post_form(
                "/agents/revoke",
                &[
                    ("csrf", &csrf),
                    ("agent_iss", &ap.issuer),
                    ("agent_sub", &helper_sub),
                ],
                Some(&alice_sid),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let (_, _, headers) = post_person(&app, &ap, &agent, "helper", "https://r1.example").await;
        let (pid4, code4) = pending_and_code(&headers);
        assert!(
            app.store
                .pending(&pid4)
                .unwrap()
                .unwrap()
                .person_id
                .is_none(),
            "unclaimed after revocation"
        );
        let (status, page) = decide(&app, &bob_sid, &code4, "approve").await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let b = app.store.binding(&ap.issuer, &helper_sub).unwrap().unwrap();
        assert!(b.is_active());
        assert_ne!(b.person_id, alice.id);
    }

    #[tokio::test]
    async fn subagent_token_binds_the_subagent_key() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let app = ui_app();
        let parent = new_agent();
        let child = new_agent();
        let (_alice, sid, _a) = enrol_person(&app, "Alice").await;
        let domain = aauth_core::ident::host_of(&ap.issuer).unwrap();
        let parent_sub = format!("aauth:planner@{domain}");
        let sub_token = ap.mint(
            "planner+search1",
            &child.jwk,
            3600,
            serde_json::json!({ "parent_agent": parent_sub }),
        );
        let ctx = agent_req(
            Method::POST,
            "/person",
            Some(
                serde_json::json!({ "resource": "https://r.example", "subagent_token": sub_token }),
            ),
            &ap,
            &parent,
            "planner",
            serde_json::json!({}),
        );
        let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let (pid, code) = pending_and_code(&headers);
        let path = format!("/consent/{pid}");
        let (_, _, _) = call_raw(
            &app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code}"), Some(&sid)),
        )
        .await;
        let (status, page, _) = call_raw(&app, Method::GET, &path, get(&path, Some(&sid))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("planner+search1"), "sub-agent shown");
        assert!(page.contains("planner@"), "parent shown");
        let (status, _) = decide_claimed(&app, &sid, &pid, "approve").await;
        assert_eq!(status, StatusCode::OK);
        let (status, body, _) = poll(&app, &ap, &parent, "planner", &pid).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let claims = verify_person_token(&app, body["person_token"].as_str().unwrap());
        assert_eq!(
            claims["cnf"]["jwk"],
            serde_json::to_value(child.jwk.public_only()).unwrap(),
            "bound to the sub-agent's key"
        );
        let rec = app
            .store
            .person_token_record(claims["jti"].as_str().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(rec.agent_sub, parent_sub, "retained under the parent");
        // Wrong parent → 400 invalid_agent_token; expired sub-agent token → 400 expired_agent_token.
        let stranger_token = ap.mint(
            "other+x",
            &child.jwk,
            3600,
            serde_json::json!({ "parent_agent": format!("aauth:other@{domain}") }),
        );
        let ctx = agent_req(
            Method::POST,
            "/person",
            Some(
                serde_json::json!({ "resource": "https://r.example", "subagent_token": stranger_token }),
            ),
            &ap,
            &parent,
            "planner",
            serde_json::json!({}),
        );
        let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_agent_token");
        assert!(hdr(&headers, "signature-error").is_none());
        let expired = ap.mint(
            "planner+search1",
            &child.jwk,
            -10,
            serde_json::json!({ "parent_agent": parent_sub }),
        );
        let ctx = agent_req(
            Method::POST,
            "/person",
            Some(serde_json::json!({ "resource": "https://r.example", "subagent_token": expired })),
            &ap,
            &parent,
            "planner",
            serde_json::json!({}),
        );
        let (status, body, _) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "expired_agent_token");
    }

    async fn decide_claimed(
        app: &Arc<App>,
        sid: &str,
        pid: &str,
        action: &str,
    ) -> (StatusCode, String) {
        let path = format!("/consent/{pid}");
        let csrf = app.store.get_session(sid).unwrap().unwrap().csrf;
        call_raw(
            app,
            Method::POST,
            &path,
            post_form(&path, &[("csrf", &csrf), ("action", action)], Some(sid)),
        )
        .await
        .into_2()
    }

    #[tokio::test]
    async fn missions_and_upstream_are_refused_while_unsupported() {
        // D-24 pin: while no mission_endpoint is advertised, mission_s256 is
        // an unsupported parameter → 400 invalid_request (not the 404/403
        // split of §Mission Endpoint Errors, which arrives with M6).
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let app = ui_app();
        let agent = new_agent();
        let (status, body, _) = call(&app, Method::POST, "/person", agent_req(Method::POST, "/person", Some(serde_json::json!({ "resource": "https://r.example", "mission_s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" })), &ap, &agent, "helper", serde_json::json!({}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");
        assert!(body["detail"].as_str().unwrap().contains("mission"));
        let (status, body, _) = call(&app, Method::POST, "/person", agent_req(Method::POST, "/person", Some(serde_json::json!({ "resource": "https://r.example", "upstream_token": "x.y.z" })), &ap, &agent, "helper", serde_json::json!({}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["detail"].as_str().unwrap().contains("upstream_token"));
        // No pending was created by the refused requests.
        assert!(app
            .store
            .recent_audit(None, 10)
            .unwrap()
            .iter()
            .all(|a| a.action != "person_token_pending"));
    }

    #[tokio::test]
    async fn distinct_resource_limit() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let mut cfg = test_config(UI_ISSUER);
        cfg.limits.resources_per_agent_per_day = 1;
        let app = build_app(cfg);
        let agent = new_agent();
        let (_alice, sid, _a) = enrol_person(&app, "Alice").await;
        let (_, _, headers) = post_person(&app, &ap, &agent, "helper", "https://r1.example").await;
        let (pid, code) = pending_and_code(&headers);
        decide(&app, &sid, &code, "approve").await;
        let (status, _, _) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::OK);
        // The same resource again is fine (already held)…
        let (status, _, _) = post_person(&app, &ap, &agent, "helper", "https://r1.example").await;
        assert_eq!(status, StatusCode::OK);
        // …a second distinct resource within the day is not.
        let (status, body, headers) =
            post_person(&app, &ap, &agent, "helper", "https://r2.example").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        assert_eq!(body["error"], "too_many_requests");
        assert!(hdr(&headers, "retry-after").is_some());
    }

    #[tokio::test]
    async fn prefer_wait_returns_the_token_on_the_initial_request() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let app = ui_app();
        let agent = new_agent();
        let (_alice, sid, _a) = enrol_person(&app, "Alice").await;
        // The agent asks with Prefer: wait=20 in the background.
        let ctx = with_prefer(
            agent_req(
                Method::POST,
                "/person",
                Some(serde_json::json!({ "resource": "https://r.example" })),
                &ap,
                &agent,
                "helper",
                serde_json::json!({}),
            ),
            20,
        );
        let app2 = app.clone();
        let started = std::time::Instant::now();
        let waiter = tokio::spawn(async move { call(&app2, Method::POST, "/person", ctx).await });
        // Meanwhile the person finds the request on the dashboard's code box —
        // we take the code from the store's pending row payload here.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let pending: Vec<crate::store::Pending> = {
            let mut found = Vec::new();
            for a in app.store.recent_audit(None, 10).unwrap() {
                if a.action == "person_token_pending" {
                    let id = a.detail["pending_id"].as_str().unwrap();
                    found.push(app.store.pending(id).unwrap().unwrap());
                }
            }
            found
        };
        assert_eq!(pending.len(), 1);
        let code = pending[0].payload["code"].as_str().unwrap().to_string();
        let (status, _) = decide(&app, &sid, &code, "approve").await;
        assert_eq!(status, StatusCode::OK);
        let (status, body, _) = waiter.await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["person_token"].as_str().is_some());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "woke on decision, not timeout"
        );
        // The delivered request is now gone for polls.
        let (status, _, _) = poll(&app, &ap, &agent, "helper", &pending[0].id).await;
        assert_eq!(status, StatusCode::GONE);
    }

    #[tokio::test]
    async fn resource_metadata_is_shown_and_sanitized() {
        // A mock resource that publishes metadata with hostile Markdown.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let resource = format!("http://127.0.0.1:{port}");
        let meta = serde_json::json!({
            "issuer": resource,
            "name": "Docs <b>Service</b>",
            "description": "Stores **your** docs. <script>alert(1)</script> [Login](https://evil.example)",
            "access_mode": "person-token",
            "logo_uri": "https://docs.example/logo.png",
        })
        .to_string();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let meta = meta.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let meta = meta.clone();
                        async move {
                            let (status, body) =
                                if req.uri().path() == "/.well-known/aauth-resource.json" {
                                    (200, meta)
                                } else {
                                    (404, "{}".to_string())
                                };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let app = ui_app();
        let agent = new_agent();
        let (_alice, sid, _a) = enrol_person(&app, "Alice").await;
        let (status, body, headers) = post_person(&app, &ap, &agent, "helper", &resource).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let (pid, code) = pending_and_code(&headers);
        let (_, _, _) = call_raw(
            &app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code}"), Some(&sid)),
        )
        .await;
        let path = format!("/consent/{pid}");
        let (status, page, _) = call_raw(&app, Method::GET, &path, get(&path, Some(&sid))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            page.contains("Docs &lt;b&gt;Service&lt;&#x2f;b&gt;"),
            "name escaped: {page}"
        );
        assert!(page.contains("<strong>your</strong>"), "markdown rendered");
        assert!(!page.contains("<script>alert(1)"), "raw html dropped");
        assert!(
            !page.contains("href=\"https://evil.example\""),
            "no clickable attacker link"
        );
        assert!(
            page.contains("evil.example"),
            "but the URL is visible as text"
        );
        assert!(
            page.contains("on your identity alone"),
            "access_mode explained"
        );
        assert!(
            page.contains(&esc("https://docs.example/logo.png")),
            "{page}"
        );
    }
}

// -------------------------------------------------------- auth tokens (/token)

mod auth_token_tests {
    use super::flow_support::*;
    use super::ui_tests::{call_raw, enrol_person, get, post_form, ui_app, UI_ISSUER};
    use super::*;

    /// What a mock resource saw at its revocation endpoint: (body, headers).
    pub(super) type RevocationSink =
        Arc<tokio::sync::Mutex<Vec<(serde_json::Value, Vec<(String, String)>)>>>;

    /// A mock resource: metadata + JWKS on loopback, mints resource tokens,
    /// records what arrives at its revocation endpoint.
    pub(super) struct MockResource {
        pub(super) issuer: String,
        pub(super) key: SigningKey,
        pub(super) kid: String,
        pub(super) revocations: RevocationSink,
        _handle: tokio::task::JoinHandle<()>,
    }

    pub(super) async fn spawn_mock_resource() -> MockResource {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{port}");
        let key = aauth_core::jwk::generate_signing_key();
        let mut jwk = Jwk::from_verifying_key(&key.verifying_key());
        jwk.kid = Some("res-key-1".into());
        let meta = serde_json::json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            "name": "Docs Service",
            "description": "Stores **your** documents.",
            "access_mode": "auth-token",
            "revocation_endpoint": format!("{issuer}/revoke"),
            "scope_descriptions": {
                "docs.read": "Read your *documents*",
                "docs.write": "Create and edit documents <b>x</b>",
                "docs.admin": "Delete everything"
            }
        })
        .to_string();
        let jwks = serde_json::json!({ "keys": [jwk] }).to_string();
        let agent_meta = serde_json::json!({
            "issuer": issuer, "jwks_uri": format!("{issuer}/.well-known/jwks.json"), "name": "Docs Service (as agent)",
        })
        .to_string();
        let revocations: RevocationSink = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let sink = revocations.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let (meta, jwks, sink, agent_meta) =
                    (meta.clone(), jwks.clone(), sink.clone(), agent_meta.clone());
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let (meta, jwks, sink, agent_meta) =
                            (meta.clone(), jwks.clone(), sink.clone(), agent_meta.clone());
                        async move {
                            let path = req.uri().path().to_string();
                            if path == "/revoke" && req.method() == Method::POST {
                                let headers: Vec<(String, String)> = req
                                    .headers()
                                    .iter()
                                    .map(|(n, v)| {
                                        (
                                            n.as_str().to_string(),
                                            v.to_str().unwrap_or("").to_string(),
                                        )
                                    })
                                    .collect();
                                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                                let body: serde_json::Value = serde_json::from_slice(&bytes)
                                    .unwrap_or(serde_json::Value::Null);
                                sink.lock().await.push((body, headers));
                                return Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder()
                                        .status(200)
                                        .header("content-type", "application/json")
                                        .body(http_body_util::Full::new(hyper::body::Bytes::from(
                                            "{}",
                                        )))
                                        .unwrap(),
                                );
                            }
                            let (status, body) = match path.as_str() {
                                "/.well-known/aauth-resource.json" => (200, meta),
                                // A resource acting as an agent publishes agent metadata too.
                                "/.well-known/aauth-agent.json" => (200, agent_meta),
                                "/.well-known/jwks.json" => (200, jwks),
                                _ => (404, "{}".to_string()),
                            };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        MockResource {
            issuer,
            key,
            kid: "res-key-1".into(),
            revocations,
            _handle: handle,
        }
    }

    impl MockResource {
        /// An agent token this resource issues to itself (call chaining: the
        /// resource is its own Agent Provider).
        pub(super) fn mint_agent_token(&self, local: &str, agent_jwk: &Jwk, ttl: i64) -> String {
            let now = aauth_core::now_unix() as i64;
            let domain = aauth_core::ident::host_of(&self.issuer).unwrap();
            jwt::sign(
                tokens::TYP_AGENT,
                Some(&self.kid),
                None,
                &serde_json::json!({
                    "iss": self.issuer, "dwk": "aauth-agent.json", "sub": format!("aauth:{local}@{domain}"),
                    "jti": aauth_core::rand_token(96), "cnf": { "jwk": agent_jwk.public_only() },
                    "iat": now, "exp": now + ttl,
                }),
                &self.key,
            )
        }

        /// Mint a resource token; `overrides` replaces/adds claims (a `null`
        /// value removes the claim).
        #[allow(clippy::too_many_arguments)]
        pub(super) fn mint(
            &self,
            ps: &str,
            sub: &str,
            presented_jti: &str,
            agent_jkt: &str,
            scope: &str,
            ttl: i64,
            overrides: serde_json::Value,
        ) -> String {
            let now = aauth_core::now_unix() as i64;
            let mut payload = serde_json::json!({
                "iss": self.issuer, "dwk": "aauth-resource.json", "aud": ps,
                "jti": aauth_core::rand_token(96), "ps": ps, "sub": sub,
                "presented_jti": presented_jti, "agent_jkt": agent_jkt,
                "iat": now, "exp": now + ttl, "scope": scope,
            });
            let mut typ = tokens::TYP_RESOURCE.to_string();
            if let Some(obj) = overrides.as_object() {
                for (k, v) in obj {
                    if k == "typ" {
                        typ = v.as_str().unwrap().to_string();
                    } else if v.is_null() {
                        payload.as_object_mut().unwrap().remove(k);
                    } else {
                        payload[k] = v.clone();
                    }
                }
            }
            jwt::sign(&typ, Some(&self.kid), None, &payload, &self.key)
        }
    }

    /// Obtain a person token for `agent` at `resource` through the full
    /// consent flow; returns (jti, sub, agent_jkt).
    pub(super) async fn person_token_for(
        app: &Arc<App>,
        ap: &MockAp,
        agent: &Agent,
        sid: &str,
        resource: &str,
    ) -> (String, String, String) {
        let (status, _, headers) = post_person(app, ap, agent, "helper", resource).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (pid, code) = pending_and_code(&headers);
        let (status, _) = decide(app, sid, &code, "approve").await;
        assert_eq!(status, StatusCode::OK);
        let (status, body, _) = poll(app, ap, agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let claims = jwt::decode(body["person_token"].as_str().unwrap())
            .unwrap()
            .payload;
        (
            claims["jti"].as_str().unwrap().to_string(),
            claims["sub"].as_str().unwrap().to_string(),
            agent.jwk.thumbprint().unwrap(),
        )
    }

    pub(super) async fn post_token(
        app: &Arc<App>,
        ap: &MockAp,
        agent: &Agent,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value, hyper::HeaderMap) {
        let ctx = agent_req(
            Method::POST,
            "/token",
            Some(body),
            ap,
            agent,
            "helper",
            serde_json::json!({}),
        );
        call(app, Method::POST, "/token", ctx).await
    }

    pub(super) fn verify_auth_token(app: &Arc<App>, token: &str) -> serde_json::Value {
        let decoded = jwt::decode(token).unwrap();
        assert_eq!(decoded.header.typ.as_deref(), Some(tokens::TYP_AUTH));
        assert_eq!(decoded.header.alg, "Ed25519");
        let key = app
            .keys
            .find_public(decoded.header.kid.as_deref().unwrap())
            .unwrap();
        jwt::verify_with_jwk(&decoded, key).unwrap();
        decoded.payload
    }

    #[tokio::test]
    async fn auth_token_end_to_end() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let res = spawn_mock_resource().await;
        let app = ui_app();
        let agent = new_agent();
        let (alice, sid, _a) = enrol_person(&app, "Alice").await;
        let (pjti, sub, jkt) = person_token_for(&app, &ap, &agent, &sid, &res.issuer).await;

        // The resource challenged the agent and issued a resource token.
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.read docs.write",
            300,
            serde_json::json!({}),
        );
        let (status, body, headers) = post_token(&app, &ap, &agent, serde_json::json!({
            "resource_token": rt,
            "justification": "I need to **edit** your notes <script>alert(1)</script> [go](https://evil.example)",
            "platform": "server", "device": "CI box",
        })).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let (pid, code) = pending_and_code(&headers);
        // Pre-claimed for Alice (the person named by the retained record).
        assert_eq!(
            app.store
                .pending(&pid)
                .unwrap()
                .unwrap()
                .person_id
                .as_deref(),
            Some(alice.id.as_str())
        );
        // The consent screen: scopes with descriptions, sanitized justification.
        let (_, _, _) = call_raw(
            &app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code}"), Some(&sid)),
        )
        .await;
        let path = format!("/consent/{pid}");
        let (status, page, _) = call_raw(&app, Method::GET, &path, get(&path, Some(&sid))).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.contains("access this service as you"));
        assert!(page.contains("docs.read") && page.contains("docs.write"));
        assert!(
            page.contains("<em>documents</em>"),
            "scope description markdown"
        );
        assert!(
            page.contains("&lt;b&gt;x&lt;&#x2f;b&gt;") || !page.contains("<b>x</b>"),
            "raw html in scope description dropped/escaped"
        );
        assert!(
            page.contains("<strong>edit</strong>"),
            "justification rendered"
        );
        assert!(!page.contains("<script>alert(1)"));
        assert!(!page.contains("href=\"https://evil.example\""));
        assert!(page.contains("Docs Service"));
        assert!(
            !page.contains("new agent"),
            "already bound: no new-agent banner"
        );
        let csrf = app.store.get_session(&sid).unwrap().unwrap().csrf;
        let (status, page, _) = call_raw(
            &app,
            Method::POST,
            &path,
            post_form(&path, &[("csrf", &csrf), ("action", "approve")], Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        // Poll → auth token.
        let (status, body, headers) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(hdr(&headers, "cache-control"), Some("no-store"));
        let token = body["auth_token"].as_str().unwrap().to_string();
        assert!(body["expires_in"].as_u64().unwrap() <= 3600);
        let claims = verify_auth_token(&app, &token);
        assert_eq!(claims["iss"], UI_ISSUER);
        assert_eq!(claims["dwk"], "aauth-person.json");
        assert_eq!(claims["aud"], res.issuer);
        assert_eq!(claims["ps"], UI_ISSUER);
        assert_eq!(claims["sub"], sub, "same directed sub as the person token");
        assert_eq!(
            claims["cnf"]["jwk"],
            serde_json::to_value(agent.jwk.public_only()).unwrap()
        );
        assert_eq!(claims["scope"], "docs.read docs.write");
        let exp = claims["exp"].as_u64().unwrap();
        let iat = claims["iat"].as_u64().unwrap();
        assert!(exp - iat <= 3600);
        for absent in ["act", "agent", "agent_jkt", "presented_jti", "may_act"] {
            assert!(claims.get(absent).is_none(), "{absent} must not appear");
        }
        let jti = claims["jti"].as_str().unwrap();
        let rec = app.store.auth_token_record(jti).unwrap().unwrap();
        assert_eq!(rec.aud, res.issuer);
        assert_eq!(rec.scope.as_deref(), Some("docs.read docs.write"));
        assert_eq!(rec.person_id, alice.id);

        // Consent on record: same scopes → 200 directly; a subset → 200; a
        // superset → 202; prompt=consent → 202; prompt=none without consent → 403.
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.read docs.write",
            300,
            serde_json::json!({}),
        );
        let (status, body, _) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let claims = verify_auth_token(&app, body["auth_token"].as_str().unwrap());
        assert_eq!(claims["sub"], sub);
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.read",
            300,
            serde_json::json!({ "account": "acct-7" }),
        );
        let (status, body, _) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let claims = verify_auth_token(&app, body["auth_token"].as_str().unwrap());
        assert_eq!(claims["scope"], "docs.read");
        assert_eq!(
            claims["account"], "acct-7",
            "account copied from the resource token"
        );
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.read docs.admin",
            300,
            serde_json::json!({}),
        );
        let (status, _, _) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "wider scope needs consent");
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.read",
            300,
            serde_json::json!({}),
        );
        let (status, _, _) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt, "prompt": "consent" }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "prompt=consent re-asks");
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.admin",
            300,
            serde_json::json!({}),
        );
        let (status, body, headers) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt, "prompt": "none" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(
            body["error"], "user_unreachable",
            "never asked, so not `denied`"
        );
        assert!(hdr(&headers, "signature-error").is_none());
        let (status, _, _) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": "x", "prompt": "banana" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Denying an auth request → 403 denied for the agent.
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.admin",
            300,
            serde_json::json!({}),
        );
        let (_, _, headers) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        let (pid2, code2) = pending_and_code(&headers);
        let (status, _) = decide(&app, &sid, &code2, "deny").await;
        assert_eq!(status, StatusCode::OK);
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid2).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(app
            .store
            .recent_audit(Some(&alice.id), 50)
            .unwrap()
            .iter()
            .any(|a| a.action == "auth_token_issued"));
    }

    #[tokio::test]
    async fn resource_token_verification_failures() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let res = spawn_mock_resource().await;
        let app = ui_app();
        let agent = new_agent();
        let (alice, sid, _a) = enrol_person(&app, "Alice").await;
        let (pjti, sub, jkt) = person_token_for(&app, &ap, &agent, &sid, &res.issuer).await;
        let ok = |o: serde_json::Value| res.mint(UI_ISSUER, &sub, &pjti, &jkt, "docs.read", 300, o);
        let cases: Vec<(&str, String, StatusCode, &str)> = vec![
            (
                "unknown presented_jti",
                res.mint(
                    UI_ISSUER,
                    &sub,
                    "pt-nope",
                    &jkt,
                    "docs.read",
                    300,
                    serde_json::json!({}),
                ),
                StatusCode::BAD_REQUEST,
                "unknown_person_token",
            ),
            (
                "sub mismatch",
                res.mint(
                    UI_ISSUER,
                    "someone-else",
                    &pjti,
                    &jkt,
                    "docs.read",
                    300,
                    serde_json::json!({}),
                ),
                StatusCode::BAD_REQUEST,
                "invalid_resource_token",
            ),
            (
                "ps mismatch",
                res.mint(
                    UI_ISSUER,
                    &sub,
                    &pjti,
                    &jkt,
                    "docs.read",
                    300,
                    serde_json::json!({ "ps": "https://other-ps.example" }),
                ),
                StatusCode::BAD_REQUEST,
                "invalid_resource_token",
            ),
            (
                "mission added (stripping in reverse)",
                ok(
                    serde_json::json!({ "mission_s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" }),
                ),
                StatusCode::BAD_REQUEST,
                "invalid_resource_token",
            ),
            (
                "tenant added",
                ok(serde_json::json!({ "tenant": "acme" })),
                StatusCode::BAD_REQUEST,
                "invalid_resource_token",
            ),
            (
                "agent_jkt of another key",
                res.mint(
                    UI_ISSUER,
                    &sub,
                    &pjti,
                    &new_agent().jwk.thumbprint().unwrap(),
                    "docs.read",
                    300,
                    serde_json::json!({}),
                ),
                StatusCode::BAD_REQUEST,
                "invalid_resource_token",
            ),
            (
                "aud is an AS (four-party)",
                ok(serde_json::json!({ "aud": "https://as.example" })),
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                "expired",
                res.mint(
                    UI_ISSUER,
                    &sub,
                    &pjti,
                    &jkt,
                    "docs.read",
                    -5,
                    serde_json::json!({}),
                ),
                StatusCode::BAD_REQUEST,
                "expired_resource_token",
            ),
            (
                "lifetime too long",
                res.mint(
                    UI_ISSUER,
                    &sub,
                    &pjti,
                    &jkt,
                    "docs.read",
                    900,
                    serde_json::json!({}),
                ),
                StatusCode::BAD_REQUEST,
                "invalid_resource_token",
            ),
            (
                "wrong typ",
                ok(serde_json::json!({ "typ": "aa-auth+jwt" })),
                StatusCode::BAD_REQUEST,
                "invalid_resource_token",
            ),
            (
                "wrong dwk",
                ok(serde_json::json!({ "dwk": "aauth-agent.json" })),
                StatusCode::BAD_REQUEST,
                "invalid_resource_token",
            ),
            (
                "interaction claim",
                ok(
                    serde_json::json!({ "interaction": { "url": "https://r.example/i", "code": "X" } }),
                ),
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                "missing presented_jti",
                ok(serde_json::json!({ "presented_jti": null })),
                StatusCode::BAD_REQUEST,
                "invalid_resource_token",
            ),
            (
                "not a jwt",
                "nope".to_string(),
                StatusCode::BAD_REQUEST,
                "invalid_resource_token",
            ),
        ];
        for (label, rt, status, error) in cases {
            let (st, body, headers) = post_token(
                &app,
                &ap,
                &agent,
                serde_json::json!({ "resource_token": rt }),
            )
            .await;
            assert_eq!(st, status, "{label}: {body}");
            assert_eq!(body["error"], error, "{label}: {body}");
            assert!(
                hdr(&headers, "signature-error").is_none(),
                "{label}: 400s carry no Signature-Error"
            );
        }
        // Mismatches were surfaced to operators, naming the claims.
        let surfaced: Vec<_> = app
            .store
            .recent_audit(Some(&alice.id), 100)
            .unwrap()
            .into_iter()
            .filter(|a| a.action == "resource_token_mismatch")
            .collect();
        // sub, ps, mission_s256, tenant reach step 6; the foreign agent_jkt
        // fails at step 5 and is not a record mismatch.
        assert_eq!(surfaced.len(), 4, "{surfaced:?}");
        assert!(surfaced.iter().any(|a| a.detail["mismatched"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "mission_s256")));
        assert!(surfaced.iter().any(|a| a.detail["mismatched"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "sub")));
        // A resource token signed by a key the resource does not publish.
        let impostor = aauth_core::jwk::generate_signing_key();
        let now = aauth_core::now_unix() as i64;
        let forged = jwt::sign(
            tokens::TYP_RESOURCE,
            Some("res-key-1"),
            None,
            &serde_json::json!({
                "iss": res.issuer, "dwk": "aauth-resource.json", "aud": UI_ISSUER, "jti": "j", "ps": UI_ISSUER,
                "sub": sub, "presented_jti": pjti, "agent_jkt": jkt, "iat": now, "exp": now + 100, "scope": "docs.read"
            }),
            &impostor,
        );
        let (st, body, _) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": forged }),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_resource_token");
        // A valid one still works after all that.
        let (st, body, _) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": ok(serde_json::json!({})) }),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED, "{body}");
    }

    #[tokio::test]
    async fn revoked_binding_denies_auth_tokens_and_someone_elses_person_token_is_refused() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let res = spawn_mock_resource().await;
        let app = ui_app();
        let agent = new_agent();
        let (_alice, sid, _a) = enrol_person(&app, "Alice").await;
        let (pjti, sub, jkt) = person_token_for(&app, &ap, &agent, &sid, &res.issuer).await;
        // Another agent presenting a resource token derived from Alice's
        // agent's person token: agent≠record.agent (and agent_jkt≠signer).
        let other = new_agent();
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &other.jwk.thumbprint().unwrap(),
            "docs.read",
            300,
            serde_json::json!({}),
        );
        let ctx = agent_req(
            Method::POST,
            "/token",
            Some(serde_json::json!({ "resource_token": rt })),
            &ap,
            &other,
            "intruder",
            serde_json::json!({}),
        );
        let (st, body, _) = call(&app, Method::POST, "/token", ctx).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_resource_token");
        // Alice revokes the agent; its next auth-token request is denied.
        let csrf = app.store.get_session(&sid).unwrap().unwrap().csrf;
        let helper_sub = format!(
            "aauth:helper@{}",
            aauth_core::ident::host_of(&ap.issuer).unwrap()
        );
        call_raw(
            &app,
            Method::POST,
            "/agents/revoke",
            post_form(
                "/agents/revoke",
                &[
                    ("csrf", &csrf),
                    ("agent_iss", &ap.issuer),
                    ("agent_sub", &helper_sub),
                ],
                Some(&sid),
            ),
        )
        .await;
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.read",
            300,
            serde_json::json!({}),
        );
        let (st, body, headers) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "denied");
        assert!(hdr(&headers, "signature-error").is_none());
    }

    #[tokio::test]
    async fn webhook_is_notified_of_pending_requests() {
        // A mock webhook receiver on loopback.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let received: Arc<tokio::sync::Mutex<Vec<serde_json::Value>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let sink = received.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let sink = sink.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let sink = sink.clone();
                        async move {
                            let bytes = req.into_body().collect().await.unwrap().to_bytes();
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                                sink.lock().await.push(v);
                            }
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(204)
                                    .body(http_body_util::Full::new(hyper::body::Bytes::new()))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let mut cfg = test_config(UI_ISSUER);
        cfg.notify.channels = vec!["web".into(), "webhook".into()];
        cfg.notify.webhook_url = Some(format!("http://127.0.0.1:{port}/hook"));
        cfg.validate().unwrap();
        let app = build_app(cfg);
        let agent = new_agent();
        let (_alice, _sid, _a) = enrol_person(&app, "Alice").await;
        let (status, _, headers) =
            post_person(&app, &ap, &agent, "helper", "https://r1.example").await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (pid, _code) = pending_and_code(&headers);
        for _ in 0..50 {
            if !received.lock().await.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let got = received.lock().await;
        assert_eq!(got.len(), 1, "webhook called once");
        assert_eq!(got[0]["event"], "pending_request");
        assert_eq!(got[0]["id"], pid);
        assert_eq!(got[0]["consent_url"], format!("{UI_ISSUER}/consent/{pid}"));
        assert!(
            got[0].get("code").is_none(),
            "the code never travels by webhook"
        );
    }
}

// -------------------------------------------------------------- revocation

mod revocation_tests {
    use super::auth_token_tests::{
        person_token_for, post_token, spawn_mock_resource, verify_auth_token,
    };
    use super::flow_support::*;
    use super::ui_tests::{call_raw, enrol_person, post_form, ui_app, UI_AUTHORITY, UI_ISSUER};
    use super::*;

    /// A request signed by a server as itself (`scheme=jwks_uri`).
    fn server_signed(
        path: &str,
        body: serde_json::Value,
        id: &str,
        dwk: &str,
        kid: &str,
        key: &SigningKey,
    ) -> ReqCtx {
        let scheme = sigkey::serialize_jwks_uri(id, dwk, kid);
        AgentReq::post(path, body)
            .authority(UI_AUTHORITY)
            .into_ctx(&scheme, key)
    }

    async fn revoke(
        app: &Arc<App>,
        ap: &MockAp,
        iss: &str,
        jti: &str,
    ) -> (StatusCode, serde_json::Value, hyper::HeaderMap) {
        let ctx = server_signed(
            "/revoke",
            serde_json::json!({ "iss": iss, "jti": jti }),
            &ap.issuer,
            "aauth-agent.json",
            &ap.kid,
            &ap.key,
        );
        call(app, Method::POST, "/revoke", ctx).await
    }

    fn agent_token_jti(token: &str) -> String {
        jwt::decode(token).unwrap().payload["jti"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn ap_revokes_agent_token_and_auth_tokens_are_swept() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let res = spawn_mock_resource().await;
        let app = ui_app();
        let agent = new_agent();
        let (alice, sid, _a) = enrol_person(&app, "Alice").await;
        // Metadata advertises where the AP revokes.
        let (_, doc, _) = body_json(crate::handlers::wellknown::person_metadata(&app)).await;
        assert_eq!(doc["revocation_endpoint"], format!("{UI_ISSUER}/revoke"));

        // The agent uses one specific agent token for the whole session.
        let token = ap.mint("helper", &agent.jwk, 3600, serde_json::json!({}));
        let jti = agent_token_jti(&token);
        let (pjti, sub, jkt) = person_token_for(&app, &ap, &agent, &sid, &res.issuer).await;
        // Get an auth token via consent.
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.read",
            300,
            serde_json::json!({}),
        );
        let (_, _, headers) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        let (pid, code) = pending_and_code(&headers);
        decide(&app, &sid, &code, "approve").await;
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let at_claims = verify_auth_token(&app, body["auth_token"].as_str().unwrap());
        let at_jti = at_claims["jti"].as_str().unwrap().to_string();
        // Make a request with `token` specifically so it is "seen".
        let ctx = AgentReq::post("/person", serde_json::json!({ "resource": res.issuer }))
            .authority(UI_AUTHORITY)
            .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
        let (status, _, _) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::OK, "consent on record");
        assert!(app
            .store
            .agent_token_seen(&ap.issuer, &jti)
            .unwrap()
            .is_some());

        // The AP revokes that agent token.
        let (status, body, _) = revoke(&app, &ap, &ap.issuer, &jti).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["revoked"], true);
        // Idempotent (a later retry; a same-second byte-identical resend would
        // be a replay to the signature layer).
        let ctx = AgentReq::post(
            "/revoke",
            serde_json::json!({ "iss": ap.issuer, "jti": jti }),
        )
        .authority(UI_AUTHORITY)
        .created(aauth_core::now_unix() + 1)
        .into_ctx(
            &sigkey::serialize_jwks_uri(&ap.issuer, "aauth-agent.json", &ap.kid),
            &ap.key,
        );
        let (status, body, _) = call(&app, Method::POST, "/revoke", ctx).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // The revoked token is denied everywhere, with a signature-layer 401.
        let ctx = AgentReq::post("/person", serde_json::json!({ "resource": res.issuer }))
            .authority(UI_AUTHORITY)
            .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
        let (status, body, headers) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(hdr(&headers, "signature-error"), Some("error=invalid_jwt"));
        assert!(body["detail"].as_str().unwrap().contains("revoked"));
        // A fresh agent token for the same agent still works (the AP decides
        // whether to issue one) — the binding is untouched.
        let (status, _, _) = post_person(&app, &ap, &agent, "helper", &res.issuer).await;
        assert_eq!(status, StatusCode::OK);
        // The auth token we issued for that agent was revoked locally and the
        // resource was told, signed by us as ourselves.
        for _ in 0..50 {
            if !res.revocations.lock().await.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let revs = res.revocations.lock().await;
        assert_eq!(revs.len(), 1, "one live auth token → one revocation");
        let (rbody, rheaders) = &revs[0];
        assert_eq!(rbody["iss"], UI_ISSUER);
        assert_eq!(rbody["jti"], at_jti);
        let sk = rheaders
            .iter()
            .find(|(n, _)| n == "signature-key")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(sk.contains("jwks_uri"), "{sk}");
        assert!(sk.contains(&format!("id=\"{UI_ISSUER}\"")), "{sk}");
        assert!(sk.contains("dwk=\"aauth-person.json\""), "{sk}");
        assert!(
            sk.contains(&format!("kid=\"{}\"", app.keys.active_kid)),
            "{sk}"
        );
        assert!(rheaders.iter().any(|(n, _)| n == "content-digest"));
        let si = rheaders
            .iter()
            .find(|(n, _)| n == "signature-input")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(
            si.contains("\"content-digest\"") && si.contains("\"content-type\""),
            "{si}"
        );
        assert!(app
            .store
            .auth_token_record(&at_jti)
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());
        let audit = app.store.recent_audit(Some(&alice.id), 50).unwrap();
        assert!(audit.iter().any(|a| a.action == "auth_token_revoked"));
        let all = app.store.recent_audit(None, 200).unwrap();
        let rev: Vec<_> = all
            .iter()
            .filter(|a| a.action == "agent_token_revoked")
            .collect();
        assert!(
            rev.iter()
                .any(|a| a.person_id.as_deref() == Some(alice.id.as_str())),
            "attributed to Alice: {rev:?}"
        );
    }

    #[tokio::test]
    async fn revoke_is_only_for_the_issuer_and_needs_jwks_uri() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let ap2 = spawn_mock_ap("ap2-key", MockApOpts::default()).await;
        let app = ui_app();
        // AP2 tries to revoke one of AP1's tokens: authenticated, but not the issuer.
        let ctx = server_signed(
            "/revoke",
            serde_json::json!({ "iss": ap.issuer, "jti": "j" }),
            &ap2.issuer,
            "aauth-agent.json",
            &ap2.kid,
            &ap2.key,
        );
        let (status, body, headers) = call(&app, Method::POST, "/revoke", ctx).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "forbidden");
        assert!(hdr(&headers, "signature-error").is_none());
        assert!(!app.store.is_agent_token_revoked(&ap.issuer, "j").unwrap());
        // An agent (jwt scheme) may not revoke.
        let agent = new_agent();
        let ctx = agent_req(
            Method::POST,
            "/revoke",
            Some(serde_json::json!({ "iss": ap.issuer, "jti": "j" })),
            &ap,
            &agent,
            "helper",
            serde_json::json!({}),
        );
        let (status, body, headers) = call(&app, Method::POST, "/revoke", ctx).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(
            hdr(&headers, "signature-error"),
            Some("error=unsupported_scheme")
        );
        assert_eq!(hdr(&headers, "accept-signature-scheme"), Some("jwks_uri"));
        // A jwks_uri signature by a key the AP does not publish.
        let impostor = aauth_core::jwk::generate_signing_key();
        let ctx = server_signed(
            "/revoke",
            serde_json::json!({ "iss": ap.issuer, "jti": "j" }),
            &ap.issuer,
            "aauth-agent.json",
            &ap.kid,
            &impostor,
        );
        let (status, _, headers) = call(&app, Method::POST, "/revoke", ctx).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            hdr(&headers, "signature-error"),
            Some("error=invalid_signature")
        );
        // Missing members.
        let ctx = server_signed(
            "/revoke",
            serde_json::json!({ "iss": ap.issuer }),
            &ap.issuer,
            "aauth-agent.json",
            &ap.kid,
            &ap.key,
        );
        let (status, body, _) = call(&app, Method::POST, "/revoke", ctx).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");
        // A token we have never seen: recorded anyway, and denied when it shows up.
        let (status, _, _) = revoke(&app, &ap, &ap.issuer, "never-seen").await;
        assert_eq!(status, StatusCode::OK);
        assert!(app
            .store
            .is_agent_token_revoked(&ap.issuer, "never-seen")
            .unwrap());
        let now = aauth_core::now_unix() as i64;
        let domain = aauth_core::ident::host_of(&ap.issuer).unwrap();
        let token = jwt::sign(
            tokens::TYP_AGENT,
            Some(&ap.kid),
            None,
            &serde_json::json!({
            "iss": ap.issuer, "dwk": "aauth-agent.json", "sub": format!("aauth:x@{domain}"), "jti": "never-seen",
            "cnf": { "jwk": agent.jwk.public_only() }, "iat": now, "exp": now + 600 }),
            &ap.key,
        );
        let ctx = AgentReq::post(
            "/person",
            serde_json::json!({ "resource": "https://r.example" }),
        )
        .authority(UI_AUTHORITY)
        .into_ctx(&sigkey::serialize_jwt(&token), &agent.key);
        let (status, _, headers) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(hdr(&headers, "signature-error"), Some("error=invalid_jwt"));
        // Our own auth token, revoked by us (signed with our own key, resolved locally).
        let ctx = server_signed(
            "/revoke",
            serde_json::json!({ "iss": UI_ISSUER, "jti": "at-unknown" }),
            UI_ISSUER,
            "aauth-person.json",
            &app.keys.active_kid,
            &app.keys.active_key,
        );
        let (status, body, _) = call(&app, Method::POST, "/revoke", ctx).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }

    #[tokio::test]
    async fn person_revoking_a_binding_sweeps_auth_tokens() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let res = spawn_mock_resource().await;
        let app = ui_app();
        let agent = new_agent();
        let (_alice, sid, _a) = enrol_person(&app, "Alice").await;
        let (pjti, sub, jkt) = person_token_for(&app, &ap, &agent, &sid, &res.issuer).await;
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.read",
            300,
            serde_json::json!({}),
        );
        let (_, _, headers) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        let (pid, code) = pending_and_code(&headers);
        decide(&app, &sid, &code, "approve").await;
        let (status, _, _) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::OK);
        // Alice revokes the agent on the dashboard.
        let csrf = app.store.get_session(&sid).unwrap().unwrap().csrf;
        let helper_sub = format!(
            "aauth:helper@{}",
            aauth_core::ident::host_of(&ap.issuer).unwrap()
        );
        let (status, _, _) = call_raw(
            &app,
            Method::POST,
            "/agents/revoke",
            post_form(
                "/agents/revoke",
                &[
                    ("csrf", &csrf),
                    ("agent_iss", &ap.issuer),
                    ("agent_sub", &helper_sub),
                ],
                Some(&sid),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        for _ in 0..50 {
            if !res.revocations.lock().await.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let revs = res.revocations.lock().await;
        assert_eq!(revs.len(), 1);
        assert_eq!(revs[0].0["iss"], UI_ISSUER);
        assert!(app
            .store
            .live_auth_tokens_for_agent(&ap.issuer, &helper_sub)
            .unwrap()
            .is_empty());
    }
}

// ---------------------------------------------------------------- missions

mod mission_tests {
    use super::auth_token_tests::{post_token, spawn_mock_resource, verify_auth_token};
    use super::flow_support::*;
    use super::ui_tests::{call_raw, enrol_person, get, post_form, UI_ISSUER};
    use super::*;

    fn mission_app() -> Arc<App> {
        let mut cfg = test_config(UI_ISSUER);
        cfg.missions.enabled = true;
        cfg.validate().unwrap();
        build_app(cfg)
    }

    async fn post_mission(
        app: &Arc<App>,
        ap: &MockAp,
        agent: &Agent,
        local: &str,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value, hyper::HeaderMap) {
        let ctx = agent_req(
            Method::POST,
            path,
            Some(body),
            ap,
            agent,
            local,
            serde_json::json!({}),
        );
        call(app, Method::POST, path, ctx).await
    }

    fn s256_of(bytes: &[u8]) -> String {
        use sha2::Digest;
        aauth_core::b64::encode(&sha2::Sha256::digest(bytes))
    }

    /// The consent screen with the mission expiry choice.
    async fn decide_mission(
        app: &Arc<App>,
        sid: &str,
        code: &str,
        action: &str,
        expires: &str,
    ) -> (StatusCode, String) {
        let (status, _, headers) = call_raw(
            app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code}"), Some(sid)),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let loc = hdr(&headers, "location").unwrap().to_string();
        let (status, page, _) = call_raw(app, Method::GET, &loc, get(&loc, Some(sid))).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let csrf = app.store.get_session(sid).unwrap().unwrap().csrf;
        let (status, body, _) = call_raw(
            app,
            Method::POST,
            &loc,
            post_form(
                &loc,
                &[("csrf", &csrf), ("action", action), ("expires", expires)],
                Some(sid),
            ),
        )
        .await;
        (status, body)
    }

    #[tokio::test]
    async fn mission_lifecycle() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let res = spawn_mock_resource().await;
        let app = mission_app();
        let agent = new_agent();
        let (alice, sid, _a) = enrol_person(&app, "Alice").await;
        // Metadata now advertises the endpoint.
        let (_, doc, _) = body_json(crate::handlers::wellknown::person_metadata(&app)).await;
        assert_eq!(doc["mission_endpoint"], format!("{UI_ISSUER}/mission"));

        // 1. Propose.
        let (status, body, headers) = post_mission(
            &app,
            &ap,
            &agent,
            "helper",
            "/mission",
            serde_json::json!({
                "description": "# Plan a trip\n\nBook **flights** for 2. <script>x</script>",
                "tools": [{ "name": "WebSearch", "description": "Search the web" }],
                "resources": [res.issuer, "https://hotels.example"],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let (pid, code) = pending_and_code(&headers);
        // Consent screen shows the proposal.
        let (_, _, h) = call_raw(
            &app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code}"), Some(&sid)),
        )
        .await;
        let loc = hdr(&h, "location").unwrap().to_string();
        let (status, page, _) = call_raw(&app, Method::GET, &loc, get(&loc, Some(&sid))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("Approve this mission"));
        assert!(page.contains("<strong>flights</strong>") && !page.contains("<script>x"));
        assert!(page.contains("WebSearch") && page.contains("Docs Service"));
        assert!(page.contains("hotels.example"));
        assert!(page.contains("name=\"expires\""));
        let csrf = app.store.get_session(&sid).unwrap().unwrap().csrf;
        let (status, page, _) = call_raw(
            &app,
            Method::POST,
            &loc,
            post_form(
                &loc,
                &[("csrf", &csrf), ("action", "approve"), ("expires", "3600")],
                Some(&sid),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.contains("Mission approved"));

        // 2. Approval response: s256 covers the exact blob bytes.
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let s256 = body["s256"].as_str().unwrap().to_string();
        let blob_bytes = aauth_core::b64::decode(body["mission"].as_str().unwrap()).unwrap();
        assert_eq!(s256, s256_of(&blob_bytes));
        let blob: serde_json::Value = serde_json::from_slice(&blob_bytes).unwrap();
        assert_eq!(blob["approver"], UI_ISSUER);
        assert!(blob["agent"].as_str().unwrap().starts_with("aauth:helper@"));
        assert_eq!(
            blob["description"],
            "# Plan a trip\n\nBook **flights** for 2. <script>x</script>"
        );
        assert_eq!(blob["approved_tools"][0]["name"], "WebSearch");
        assert_eq!(
            blob["approved_resources"],
            serde_json::json!([res.issuer, "https://hotels.example"])
        );
        let now = aauth_core::now_unix();
        let approved_at = crate::ui::parse_iso8601(blob["approved_at"].as_str().unwrap()).unwrap();
        let expires_at = crate::ui::parse_iso8601(blob["expires_at"].as_str().unwrap()).unwrap();
        assert!(approved_at <= now && now - approved_at < 10);
        assert!(expires_at > now + 3500 && expires_at <= now + 3600);
        // A person token per approved resource, carrying mission_s256, capped by expires_at.
        let pt = body["person_tokens"][&res.issuer]
            .as_str()
            .expect("token for the docs service");
        let claims = jwt::decode(pt).unwrap().payload;
        assert_eq!(claims["mission_s256"], s256);
        assert!(claims["exp"].as_u64().unwrap() <= expires_at);
        assert!(body["person_tokens"]["https://hotels.example"].is_string());
        let pjti = claims["jti"].as_str().unwrap().to_string();
        let sub = claims["sub"].as_str().unwrap().to_string();
        assert_eq!(
            app.store
                .person_token_record(&pjti)
                .unwrap()
                .unwrap()
                .mission_s256
                .as_deref(),
            Some(s256.as_str())
        );
        // Bound and consented as a side effect.
        assert!(app
            .store
            .binding(&ap.issuer, blob["agent"].as_str().unwrap())
            .unwrap()
            .unwrap()
            .is_active());
        let stored = app.store.mission(&s256).unwrap().unwrap();
        assert!(stored.is_active());
        assert_eq!(
            stored.blob, blob_bytes,
            "the stored bytes are the served bytes"
        );

        // 3. Person tokens under the mission: consent on record → 200 with
        //    mission_s256; a new resource → 202 then token carries it too.
        let ctx = agent_req(
            Method::POST,
            "/person",
            Some(serde_json::json!({ "resource": res.issuer, "mission_s256": s256 })),
            &ap,
            &agent,
            "helper",
            serde_json::json!({}),
        );
        let (status, body, _) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let c = jwt::decode(body["person_token"].as_str().unwrap())
            .unwrap()
            .payload;
        assert_eq!(c["mission_s256"], s256);
        assert!(c["exp"].as_u64().unwrap() <= expires_at);
        let ctx = agent_req(
            Method::POST,
            "/person",
            Some(serde_json::json!({ "resource": "https://cars.example", "mission_s256": s256 })),
            &ap,
            &agent,
            "helper",
            serde_json::json!({}),
        );
        let (status, _, headers) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (pid2, code2) = pending_and_code(&headers);
        let (status, _) = decide(&app, &sid, &code2, "approve").await;
        assert_eq!(status, StatusCode::OK);
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid2).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            jwt::decode(body["person_token"].as_str().unwrap())
                .unwrap()
                .payload["mission_s256"],
            s256
        );

        // 4. Update: accepted, digested, logged; nothing else changes.
        let upd = "# Hotel unavailable\n\nProposing a comparable one.";
        let (status, body, _) = post_mission(
            &app,
            &ap,
            &agent,
            "helper",
            &format!("/mission/{s256}"),
            serde_json::json!({ "action": "update", "description": upd }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["s256"], s256_of(upd.as_bytes()));
        let log = app.store.mission_log(&s256).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].kind, "update");
        assert_eq!(app.store.mission(&s256).unwrap().unwrap().blob, blob_bytes);
        let (_, dash, _) = call_raw(&app, Method::GET, "/", get("/", Some(&sid))).await;
        assert!(dash.contains("1 update(s)") && dash.contains("Hotel unavailable"));
        assert!(dash.contains("End mission"));

        // 5. Auth token under the mission: the resource token must carry the
        //    same mission_s256 (stripping it is a step-6 mismatch, surfaced).
        let jkt = agent.jwk.thumbprint().unwrap();
        let stripped = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.read",
            300,
            serde_json::json!({}),
        );
        let (status, body, _) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": stripped }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_resource_token");
        assert!(app
            .store
            .recent_audit(Some(&alice.id), 50)
            .unwrap()
            .iter()
            .any(|a| a.action == "resource_token_mismatch"
                && a.detail["mismatched"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|m| m == "mission_s256")));
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.read",
            300,
            serde_json::json!({ "mission_s256": s256 }),
        );
        let (status, body, headers) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let (pid3, code3) = pending_and_code(&headers);
        decide(&app, &sid, &code3, "approve").await;
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid3).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let at = verify_auth_token(&app, body["auth_token"].as_str().unwrap());
        assert_eq!(at["mission_s256"], s256);
        assert!(at["exp"].as_u64().unwrap() <= expires_at);
        let at_jti = at["jti"].as_str().unwrap().to_string();

        // 6. Completion: proposed, accepted by the person, mission ends.
        let (status, _, headers) = post_mission(
            &app,
            &ap,
            &agent,
            "helper",
            &format!("/mission/{s256}"),
            serde_json::json!({ "action": "completion", "summary": "Booked **everything**." }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (pid4, code4) = pending_and_code(&headers);
        let (status, page) = decide_mission(&app, &sid, &code4, "approve", "").await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.contains("Mission completed"));
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid4).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["s256"], s256);
        assert_eq!(body["termination_reason"], "completed");
        // Terminated is deliberately distinguishable for the owner.
        let (status, body, headers) = post_mission(
            &app,
            &ap,
            &agent,
            "helper",
            &format!("/mission/{s256}"),
            serde_json::json!({ "action": "update", "description": "more" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "mission_terminated");
        assert_eq!(body["mission_status"], "terminated");
        assert_eq!(body["termination_reason"], "completed");
        assert!(hdr(&headers, "signature-error").is_none());
        let ctx = agent_req(
            Method::POST,
            "/person",
            Some(serde_json::json!({ "resource": res.issuer, "mission_s256": s256 })),
            &ap,
            &agent,
            "helper",
            serde_json::json!({}),
        );
        let (status, body, _) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "mission_terminated");
        let rt = res.mint(
            UI_ISSUER,
            &sub,
            &pjti,
            &jkt,
            "docs.read",
            300,
            serde_json::json!({ "mission_s256": s256 }),
        );
        let (status, body, _) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "mission_terminated");
        // The auth token issued under the mission is still recorded (it
        // expires on its own; completion is not revocation).
        assert!(app.store.auth_token_record(&at_jti).unwrap().is_some());
        let log = app.store.mission_log(&s256).unwrap();
        assert!(log.iter().any(|e| e.kind == "completed"));
    }

    #[tokio::test]
    async fn not_found_and_not_owned_are_one_answer() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let app = mission_app();
        let owner = new_agent();
        let other = new_agent();
        let (_alice, sid, _a) = enrol_person(&app, "Alice").await;
        // Owner gets a mission.
        let (_, _, headers) = post_mission(
            &app,
            &ap,
            &owner,
            "owner",
            "/mission",
            serde_json::json!({ "description": "d" }),
        )
        .await;
        let (pid, code) = pending_and_code(&headers);
        decide_mission(&app, &sid, &code, "approve", "86400").await;
        let (status, body, _) = poll(&app, &ap, &owner, "owner", &pid).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let s256 = body["s256"].as_str().unwrap().to_string();
        let random = aauth_core::b64::encode(&[7u8; 32]);
        let update = |_s: &str| serde_json::json!({ "action": "update", "description": "x" });
        // Not owned (other agent, real mission) and unknown (owner, random id):
        // identical status, error, body and headers.
        let (s1, b1, h1) = post_mission(
            &app,
            &ap,
            &other,
            "other",
            &format!("/mission/{s256}"),
            update(&s256),
        )
        .await;
        let (s2, b2, h2) = post_mission(
            &app,
            &ap,
            &owner,
            "owner",
            &format!("/mission/{random}"),
            update(&random),
        )
        .await;
        assert_eq!(s1, StatusCode::NOT_FOUND, "{b1}");
        assert_eq!(s2, StatusCode::NOT_FOUND, "{b2}");
        assert_eq!(b1, b2);
        assert_eq!(b1["error"], "mission_not_found");
        let names = |h: &hyper::HeaderMap| {
            let mut v: Vec<String> = h
                .iter()
                .map(|(n, val)| format!("{n}: {}", val.to_str().unwrap_or("")))
                .collect();
            v.sort();
            v
        };
        assert_eq!(names(&h1), names(&h2));
        assert!(hdr(&h1, "signature-error").is_none());
        // Timing: both paths run the same query and comparison. Compare
        // medians of the handler alone (signature verification is common to
        // both and dominates, so measure the lookup itself).
        let owner_signer = {
            let ctx = agent_req(
                Method::POST,
                "/person",
                Some(serde_json::json!({})),
                &ap,
                &owner,
                "owner",
                serde_json::json!({}),
            );
            // Build a signer struct by verifying a real request.
            crate::reqctx::verify_agent_request(&ctx, &app, true)
                .await
                .unwrap()
        };
        let other_signer = {
            let ctx = agent_req(
                Method::POST,
                "/person",
                Some(serde_json::json!({})),
                &ap,
                &other,
                "other",
                serde_json::json!({}),
            );
            crate::reqctx::verify_agent_request(&ctx, &app, true)
                .await
                .unwrap()
        };
        let mut t_unknown = Vec::new();
        let mut t_not_owned = Vec::new();
        for i in 0..400 {
            let start = std::time::Instant::now();
            let r = crate::handlers::mission::lookup_owned(
                &app,
                if i % 2 == 0 { &random } else { &s256 },
                if i % 2 == 0 {
                    &owner_signer
                } else {
                    &other_signer
                },
            )
            .unwrap();
            let el = start.elapsed();
            assert!(matches!(
                r,
                crate::handlers::mission::Lookup::NotFoundOrNotOwned
            ));
            if i % 2 == 0 {
                t_unknown.push(el)
            } else {
                t_not_owned.push(el)
            }
        }
        t_unknown.sort();
        t_not_owned.sort();
        let (mu, mo) = (
            t_unknown[t_unknown.len() / 2],
            t_not_owned[t_not_owned.len() / 2],
        );
        let ratio = mu.as_secs_f64().max(mo.as_secs_f64())
            / mu.as_secs_f64().min(mo.as_secs_f64()).max(1e-9);
        assert!(
            ratio < 3.0,
            "medians differ too much: unknown {mu:?} vs not-owned {mo:?}"
        );
        // Malformed segment and unknown action are 400s regardless.
        let (status, body, _) = post_mission(
            &app,
            &ap,
            &owner,
            "owner",
            "/mission/not-a-digest",
            update("x"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body, _) = post_mission(
            &app,
            &ap,
            &owner,
            "owner",
            &format!("/mission/{s256}"),
            serde_json::json!({ "action": "explode" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body, _) = post_mission(
            &app,
            &ap,
            &owner,
            "owner",
            &format!("/mission/{s256}"),
            serde_json::json!({ "description": "no action" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        // /person naming someone else's mission → the same 404.
        let ctx = agent_req(
            Method::POST,
            "/person",
            Some(serde_json::json!({ "resource": "https://r.example", "mission_s256": s256 })),
            &ap,
            &other,
            "other",
            serde_json::json!({}),
        );
        let (status, body, _) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"], "mission_not_found");
        // With missions disabled the endpoint does not exist and the
        // parameter is refused (pinned behaviour).
        let off = ui_tests::ui_app();
        let (status, _, _) = post_mission(
            &off,
            &ap,
            &owner,
            "owner",
            "/mission",
            serde_json::json!({ "description": "d" }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn expiry_and_ending_a_mission() {
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let res = spawn_mock_resource().await;
        let app = mission_app();
        let agent = new_agent();
        let (alice, sid, _a) = enrol_person(&app, "Alice").await;
        // Approve with a one-second lifetime straight through consent.rs.
        let (_, _, headers) = post_mission(
            &app,
            &ap,
            &agent,
            "helper",
            "/mission",
            serde_json::json!({ "description": "short", "resources": [res.issuer] }),
        )
        .await;
        let (pid, code) = pending_and_code(&headers);
        let (_, _, h) = call_raw(
            &app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code}"), Some(&sid)),
        )
        .await;
        let _ = h;
        let pr = app.store.pending(&pid).unwrap().unwrap();
        let outcome =
            crate::consent::approve_mission(&app, &alice.id, &pr, "cli", Some(1)).unwrap();
        let s256 = match outcome {
            crate::consent::ApproveOutcome::Approved { jti, .. } => jti,
            o => panic!("{o:?}"),
        };
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let pt = body["person_tokens"][&res.issuer].as_str().unwrap();
        let claims = jwt::decode(pt).unwrap().payload;
        let now = aauth_core::now_unix();
        assert!(
            claims["exp"].as_u64().unwrap() <= now + 1,
            "capped by expires_at"
        );
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        // Expired: every decision path reports mission_terminated / expired.
        let ctx = agent_req(
            Method::POST,
            "/person",
            Some(serde_json::json!({ "resource": res.issuer, "mission_s256": s256 })),
            &ap,
            &agent,
            "helper",
            serde_json::json!({}),
        );
        let (status, body, _) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "mission_terminated");
        assert_eq!(body["termination_reason"], "expired");
        assert_eq!(
            app.store
                .mission(&s256)
                .unwrap()
                .unwrap()
                .termination_reason
                .as_deref(),
            Some("expired")
        );

        // A second mission, ended from the dashboard: auth tokens under it
        // are revoked at the resource.
        let (status, body, headers) = post_mission(
            &app,
            &ap,
            &agent,
            "helper",
            "/mission",
            serde_json::json!({ "description": "long", "resources": [res.issuer] }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let (pid2, code2) = pending_and_code(&headers);
        decide_mission(&app, &sid, &code2, "approve", "86400").await;
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid2).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let s2 = body["s256"].as_str().unwrap().to_string();
        let pt = jwt::decode(body["person_tokens"][&res.issuer].as_str().unwrap())
            .unwrap()
            .payload;
        let jkt = agent.jwk.thumbprint().unwrap();
        let rt = res.mint(
            UI_ISSUER,
            pt["sub"].as_str().unwrap(),
            pt["jti"].as_str().unwrap(),
            &jkt,
            "docs.read",
            300,
            serde_json::json!({ "mission_s256": s2 }),
        );
        let (status, body, headers) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let (pid3, code3) = pending_and_code(&headers);
        decide(&app, &sid, &code3, "approve").await;
        let (status, _, _) = poll(&app, &ap, &agent, "helper", &pid3).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            app.store.live_auth_tokens_for_mission(&s2).unwrap().len(),
            1
        );
        let csrf = app.store.get_session(&sid).unwrap().unwrap().csrf;
        let (status, _, _) = call_raw(
            &app,
            Method::POST,
            "/missions/end",
            post_form(
                "/missions/end",
                &[("csrf", &csrf), ("s256", &s2)],
                Some(&sid),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let m = app.store.mission(&s2).unwrap().unwrap();
        assert!(!m.is_active());
        assert_eq!(m.termination_reason.as_deref(), Some("revoked"));
        for _ in 0..50 {
            if !res.revocations.lock().await.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            res.revocations.lock().await.len(),
            1,
            "the auth token under the mission was revoked at the resource"
        );
        assert!(app
            .store
            .live_auth_tokens_for_mission(&s2)
            .unwrap()
            .is_empty());
        // Bob cannot end Alice's mission... there is only Alice here; the
        // CSRF-less attempt is refused.
        let (status, _, _) = call_raw(
            &app,
            Method::POST,
            "/missions/end",
            post_form("/missions/end", &[("s256", &s2)], Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}

// ------------------------------------------ AS federation and call chaining

mod federation_tests {
    use super::auth_token_tests::{
        person_token_for, post_token, spawn_mock_resource, MockResource,
    };
    use super::flow_support::*;
    use super::ui_tests::{enrol_person, UI_AUTHORITY, UI_ISSUER};
    use super::*;

    /// How the mock Access Server behaves.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum AsMode {
        Direct,
        ClaimsThenDirect,
        Interaction,
        Deny,
        Payment,
        BadAudience,
    }

    /// Requests a mock AS saw: (method, path, headers, body).
    type SeenRequests =
        Arc<tokio::sync::Mutex<Vec<(String, String, Vec<(String, String)>, serde_json::Value)>>>;

    struct MockAs {
        issuer: String,
        /// Flip to let a pending `Interaction` complete on the next poll.
        done: Arc<std::sync::atomic::AtomicBool>,
        seen: SeenRequests,
        _handle: tokio::task::JoinHandle<()>,
    }

    async fn spawn_mock_as(mode: AsMode) -> MockAs {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{port}");
        let key = aauth_core::jwk::generate_signing_key();
        let mut jwk = Jwk::from_verifying_key(&key.verifying_key());
        jwk.kid = Some("as-key-1".into());
        let meta = serde_json::json!({
            "issuer": issuer, "name": "Mock Access Server",
            "auth_token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        })
        .to_string();
        let jwks = serde_json::json!({ "keys": [jwk] }).to_string();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen: SeenRequests = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let (issuer2, key2, done2, seen2) =
            (issuer.clone(), key.clone(), done.clone(), seen.clone());
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let (meta, jwks, issuer, key, done, seen) = (
                    meta.clone(),
                    jwks.clone(),
                    issuer2.clone(),
                    key2.clone(),
                    done2.clone(),
                    seen2.clone(),
                );
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let (meta, jwks, issuer, key, done, seen) = (
                            meta.clone(),
                            jwks.clone(),
                            issuer.clone(),
                            key.clone(),
                            done.clone(),
                            seen.clone(),
                        );
                        async move {
                            let method = req.method().to_string();
                            let path = req.uri().path().to_string();
                            let headers: Vec<(String, String)> = req
                                .headers()
                                .iter()
                                .map(|(n, v)| {
                                    (n.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                                })
                                .collect();
                            let bytes = req.into_body().collect().await.unwrap().to_bytes();
                            let body: serde_json::Value =
                                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
                            seen.lock().await.push((
                                method.clone(),
                                path.clone(),
                                headers.clone(),
                                body.clone(),
                            ));
                            let mint = |body: &serde_json::Value, bad_aud: bool| -> String {
                                // The AS's auth token for the resource token in the request.
                                let rt = jwt::decode(body["resource_token"].as_str().unwrap())
                                    .unwrap()
                                    .payload;
                                let at = jwt::decode(body["agent_token"].as_str().unwrap())
                                    .unwrap()
                                    .payload;
                                let now = aauth_core::now_unix() as i64;
                                jwt::sign(
                                    tokens::TYP_AUTH,
                                    Some("as-key-1"),
                                    None,
                                    &serde_json::json!({
                                        "iss": issuer, "dwk": "aauth-access.json",
                                        "aud": if bad_aud { "https://elsewhere.example".to_string() } else { rt["iss"].as_str().unwrap().to_string() },
                                        "jti": aauth_core::rand_token(96), "ps": rt["ps"], "sub": rt["sub"],
                                        "cnf": at["cnf"], "scope": rt["scope"], "iat": now, "exp": now + 900,
                                    }),
                                    &key,
                                )
                            };
                            let (status, hdrs, resp): (u16, Vec<(&str, String)>, String) = match (
                                method.as_str(),
                                path.as_str(),
                            ) {
                                ("GET", "/.well-known/aauth-access.json") => (200, vec![], meta),
                                ("GET", "/.well-known/jwks.json") => (200, vec![], jwks),
                                ("POST", "/token") => {
                                    // The PS must sign as itself with jwks_uri and cover the body.
                                    let sk = headers
                                        .iter()
                                        .find(|(n, _)| n == "signature-key")
                                        .map(|(_, v)| v.clone())
                                        .unwrap_or_default();
                                    let si = headers
                                        .iter()
                                        .find(|(n, _)| n == "signature-input")
                                        .map(|(_, v)| v.clone())
                                        .unwrap_or_default();
                                    let has_digest =
                                        headers.iter().any(|(n, _)| n == "content-digest");
                                    if !sk.contains("jwks_uri")
                                        || !si.contains("\"content-digest\"")
                                        || !has_digest
                                        || body.get("resource_token").is_none()
                                        || body.get("agent_token").is_none()
                                    {
                                        (401, vec![], serde_json::json!({"error":"invalid_signature","detail":"mock AS: expected jwks_uri-signed POST covering the body"}).to_string())
                                    } else {
                                        match mode {
                                            AsMode::Direct => (200, vec![], serde_json::json!({ "auth_token": mint(&body, false), "expires_in": 900 }).to_string()),
                                            AsMode::BadAudience => (200, vec![], serde_json::json!({ "auth_token": mint(&body, true), "expires_in": 900 }).to_string()),
                                            AsMode::ClaimsThenDirect => (202, vec![("location", format!("{issuer}/pending/c1")), ("aauth-requirement", "requirement=claims".into()), ("retry-after", "0".into())], serde_json::json!({ "status": "pending", "required_claims": ["sub"] }).to_string()),
                                            AsMode::Interaction => (202, vec![("location", format!("{issuer}/pending/i1")), ("aauth-requirement", format!("requirement=interaction; url=\"{issuer}/interact\"; code=\"ASAS-1234\"")), ("retry-after", "0".into())], serde_json::json!({ "status": "pending" }).to_string()),
                                            AsMode::Deny => (403, vec![], serde_json::json!({ "error": "denied", "detail": "resource policy" }).to_string()),
                                            AsMode::Payment => (402, vec![("location", format!("{issuer}/pending/p1"))], "{}".into()),
                                        }
                                    }
                                }
                                ("POST", "/pending/c1") => {
                                    // The claims round: the PS answers with the directed sub.
                                    if body.get("sub").is_none() {
                                        (
                                            400,
                                            vec![],
                                            serde_json::json!({"error":"invalid_request"})
                                                .to_string(),
                                        )
                                    } else {
                                        // Re-mint using the original request stored earlier.
                                        let seen_g = seen.lock().await;
                                        let orig = seen_g
                                            .iter()
                                            .find(|(m, p, _, _)| m == "POST" && p == "/token")
                                            .map(|(_, _, _, b)| b.clone())
                                            .unwrap();
                                        drop(seen_g);
                                        (200, vec![], serde_json::json!({ "auth_token": mint(&orig, false), "expires_in": 900 }).to_string())
                                    }
                                }
                                ("GET", "/pending/i1") => {
                                    if done.load(std::sync::atomic::Ordering::SeqCst) {
                                        let seen_g = seen.lock().await;
                                        let orig = seen_g
                                            .iter()
                                            .find(|(m, p, _, _)| m == "POST" && p == "/token")
                                            .map(|(_, _, _, b)| b.clone())
                                            .unwrap();
                                        drop(seen_g);
                                        (200, vec![], serde_json::json!({ "auth_token": mint(&orig, false), "expires_in": 900 }).to_string())
                                    } else {
                                        (202, vec![("location", format!("{issuer}/pending/i1")), ("aauth-requirement", format!("requirement=interaction; url=\"{issuer}/interact\"; code=\"ASAS-1234\"")), ("retry-after", "0".into())], serde_json::json!({ "status": "pending" }).to_string())
                                    }
                                }
                                _ => (404, vec![], "{}".into()),
                            };
                            let mut b = hyper::Response::builder()
                                .status(status)
                                .header("content-type", "application/json");
                            for (n, v) in hdrs {
                                b = b.header(n, v);
                            }
                            Ok::<_, std::convert::Infallible>(
                                b.body(http_body_util::Full::new(hyper::body::Bytes::from(resp)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        MockAs {
            issuer,
            done,
            seen,
            _handle: handle,
        }
    }

    fn fed_app() -> Arc<App> {
        let mut cfg = test_config(UI_ISSUER);
        cfg.federation.enabled = true;
        cfg.validate().unwrap();
        build_app(cfg)
    }

    /// Resource token whose `aud` is the Access Server (four-party).
    fn rt_for_as(
        res: &MockResource,
        as_iss: &str,
        sub: &str,
        pjti: &str,
        jkt: &str,
        scope: &str,
    ) -> String {
        res.mint(
            UI_ISSUER,
            sub,
            pjti,
            jkt,
            scope,
            300,
            serde_json::json!({ "aud": as_iss }),
        )
    }

    #[tokio::test]
    async fn four_party_direct_grant_and_claims_round() {
        for mode in [AsMode::Direct, AsMode::ClaimsThenDirect] {
            let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
            let res = spawn_mock_resource().await;
            let acc = spawn_mock_as(mode).await;
            let app = fed_app();
            let agent = new_agent();
            let (alice, sid, _a) = enrol_person(&app, "Alice").await;
            let (pjti, sub, jkt) = person_token_for(&app, &ap, &agent, &sid, &res.issuer).await;
            let rt = rt_for_as(&res, &acc.issuer, &sub, &pjti, &jkt, "docs.read");
            // Consent first (202), then the AS.
            let (status, body, headers) = post_token(
                &app,
                &ap,
                &agent,
                serde_json::json!({ "resource_token": rt }),
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED, "{mode:?}: {body}");
            let (pid, code) = pending_and_code(&headers);
            let (status, _) = decide(&app, &sid, &code, "approve").await;
            assert_eq!(status, StatusCode::OK);
            let (status, body, headers) = poll(&app, &ap, &agent, "helper", &pid).await;
            assert_eq!(status, StatusCode::OK, "{mode:?}: {body}");
            assert_eq!(hdr(&headers, "cache-control"), Some("no-store"));
            let token = body["auth_token"].as_str().unwrap();
            let claims = jwt::decode(token).unwrap().payload;
            assert_eq!(claims["iss"], acc.issuer, "issued by the AS");
            assert_eq!(claims["dwk"], "aauth-access.json");
            assert_eq!(claims["aud"], res.issuer);
            assert_eq!(claims["sub"], sub);
            assert_eq!(claims["cnf"]["jwk"]["x"], agent.jwk.x);
            // Recorded as provided (iss = AS) so it can be revoked at the resource.
            let rec = app
                .store
                .auth_token_record(claims["jti"].as_str().unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(rec.iss.as_deref(), Some(acc.issuer.as_str()));
            assert_eq!(rec.person_id, alice.id);
            // The AS saw a jwks_uri-signed POST from us with the agent token forwarded.
            let seen = acc.seen.lock().await;
            let (_, _, hdrs, b) = seen
                .iter()
                .find(|(m, p, _, _)| m == "POST" && p == "/token")
                .unwrap();
            let sk = hdrs
                .iter()
                .find(|(n, _)| n == "signature-key")
                .map(|(_, v)| v.clone())
                .unwrap();
            assert!(
                sk.contains(&format!("id=\"{UI_ISSUER}\""))
                    && sk.contains("dwk=\"aauth-person.json\""),
                "{sk}"
            );
            assert!(b["agent_token"].is_string() && b["resource_token"].is_string());
            if mode == AsMode::ClaimsThenDirect {
                let claims_post = seen
                    .iter()
                    .find(|(m, p, _, _)| m == "POST" && p == "/pending/c1")
                    .expect("claims answered");
                assert_eq!(claims_post.3["sub"], sub, "we asserted the directed sub");
            }
            drop(seen);
            // Consent on record → straight to the AS → 200 without a pending.
            let rt = rt_for_as(&res, &acc.issuer, &sub, &pjti, &jkt, "docs.read");
            let (status, body, _) = post_token(
                &app,
                &ap,
                &agent,
                serde_json::json!({ "resource_token": rt }),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{mode:?}: {body}");
            assert!(app
                .store
                .recent_audit(Some(&alice.id), 50)
                .unwrap()
                .iter()
                .any(|a| a.action == "auth_token_provided"));
        }
    }

    #[tokio::test]
    async fn four_party_interaction_deny_payment_and_bad_token() {
        // Interaction: the AS's requirement is forwarded to the agent; when the
        // AS is satisfied, the next poll delivers the token.
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let res = spawn_mock_resource().await;
        let acc = spawn_mock_as(AsMode::Interaction).await;
        let app = fed_app();
        let agent = new_agent();
        let (_alice, sid, _a) = enrol_person(&app, "Alice").await;
        let (pjti, sub, jkt) = person_token_for(&app, &ap, &agent, &sid, &res.issuer).await;
        let rt = rt_for_as(&res, &acc.issuer, &sub, &pjti, &jkt, "docs.read");
        let (_, _, headers) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        let (pid, code) = pending_and_code(&headers);
        decide(&app, &sid, &code, "approve").await;
        let (status, body, headers) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let req = hdr(&headers, "aauth-requirement").unwrap();
        assert!(
            req.contains("requirement=interaction")
                && req.contains("ASAS-1234")
                && req.contains(&acc.issuer),
            "AS requirement forwarded: {req}"
        );
        assert!(
            hdr(&headers, "location")
                .unwrap()
                .starts_with(&format!("{UI_ISSUER}/pending/")),
            "our Location, not the AS's"
        );
        // Still pending on the AS side.
        let (status, _, _) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        acc.done.store(true, std::sync::atomic::Ordering::SeqCst);
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            jwt::decode(body["auth_token"].as_str().unwrap())
                .unwrap()
                .payload["iss"],
            acc.issuer
        );
        let (status, _, _) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::GONE, "delivered once");

        // Deny, payment, bad token — with consent already on record.
        for (mode, want_status, want_error) in [
            (AsMode::Deny, StatusCode::FORBIDDEN, "denied"),
            (AsMode::Payment, StatusCode::FORBIDDEN, "user_unreachable"),
            (AsMode::BadAudience, StatusCode::BAD_GATEWAY, "server_error"),
        ] {
            let acc = spawn_mock_as(mode).await;
            let rt = rt_for_as(&res, &acc.issuer, &sub, &pjti, &jkt, "docs.read");
            let (status, body, headers) = post_token(
                &app,
                &ap,
                &agent,
                serde_json::json!({ "resource_token": rt }),
            )
            .await;
            assert_eq!(status, want_status, "{mode:?}: {body}");
            assert_eq!(body["error"], want_error, "{mode:?}: {body}");
            assert!(hdr(&headers, "signature-error").is_none());
        }
        // Federation disabled → the foreign aud is refused before any call.
        let off = ui_tests::ui_app();
        let (_alice2, sid2, _a2) = enrol_person(&off, "Alice").await;
        let (pjti2, sub2, _) = person_token_for(&off, &ap, &agent, &sid2, &res.issuer).await;
        let rt = rt_for_as(&res, &acc.issuer, &sub2, &pjti2, &jkt, "docs.read");
        let (status, body, _) = post_token(
            &off,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["detail"].as_str().unwrap().contains("not enabled"));
    }

    #[tokio::test]
    async fn call_chaining_end_to_end() {
        // R1: a resource that also acts as an agent (its own Agent Provider).
        // R2: a further resource downstream.
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let r1 = spawn_mock_resource().await;
        let r2 = spawn_mock_resource().await;
        let app = fed_app();
        let agent = new_agent();
        let (alice, sid, _a) = enrol_person(&app, "Alice").await;
        // 1. Alice's agent gets an auth token for R1 (three-party).
        let (pjti1, sub1, jkt) = person_token_for(&app, &ap, &agent, &sid, &r1.issuer).await;
        let rt1 = r1.mint(
            UI_ISSUER,
            &sub1,
            &pjti1,
            &jkt,
            "docs.read",
            300,
            serde_json::json!({}),
        );
        let (_, _, headers) = post_token(
            &app,
            &ap,
            &agent,
            serde_json::json!({ "resource_token": rt1 }),
        )
        .await;
        let (pid, code) = pending_and_code(&headers);
        decide(&app, &sid, &code, "approve").await;
        let (status, body, _) = poll(&app, &ap, &agent, "helper", &pid).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let at1 = body["auth_token"].as_str().unwrap().to_string();
        // 2. R1, acting as an agent with its own identity, asks for a person
        //    token at R2 with AT1 as upstream. It signs with its own key and
        //    an agent token it issued to itself (iss = R1).
        let r1_agent = new_agent();
        let r1_domain = aauth_core::ident::host_of(&r1.issuer).unwrap();
        let r1_token = r1.mint_agent_token("svc", &r1_agent.jwk, 3600);
        let r1_req = |path: &str, body: serde_json::Value| {
            AgentReq::post(path, body)
                .authority(UI_AUTHORITY)
                .into_ctx(&sigkey::serialize_jwt(&r1_token), &r1_agent.key)
        };
        let (status, body, headers) = call(
            &app,
            Method::POST,
            "/person",
            r1_req(
                "/person",
                serde_json::json!({ "resource": r2.issuer, "upstream_token": at1 }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let (pid2, code2) = pending_and_code(&headers);
        // Pre-claimed for Alice (the upstream token's person), and the screen says it is chained.
        assert_eq!(
            app.store
                .pending(&pid2)
                .unwrap()
                .unwrap()
                .person_id
                .as_deref(),
            Some(alice.id.as_str())
        );
        let (_, _, h) = ui_tests::call_raw(
            &app,
            Method::GET,
            "/consent",
            ui_tests::get(&format!("/consent?code={code2}"), Some(&sid)),
        )
        .await;
        let loc = hdr(&h, "location").unwrap().to_string();
        let (status, page, _) =
            ui_tests::call_raw(&app, Method::GET, &loc, ui_tests::get(&loc, Some(&sid))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            page.contains("Chained")
                && page.contains("acting on an authorization you gave earlier"),
            "{page}"
        );
        let csrf = app.store.get_session(&sid).unwrap().unwrap().csrf;
        let (status, _, _) = ui_tests::call_raw(
            &app,
            Method::POST,
            &loc,
            ui_tests::post_form(&loc, &[("csrf", &csrf), ("action", "approve")], Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let path = format!("/pending/{pid2}");
        let mut get_ctx = AgentReq {
            method: Method::GET,
            authority: UI_AUTHORITY.into(),
            path: path.clone(),
            body: vec![],
            cover_body: false,
            digest_override: None,
            created: None,
        }
        .into_ctx(&sigkey::serialize_jwt(&r1_token), &r1_agent.key);
        get_ctx.method = "GET".into();
        let (status, body, _) = call(&app, Method::GET, &path, get_ctx).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let pt2 = jwt::decode(body["person_token"].as_str().unwrap())
            .unwrap()
            .payload;
        assert_eq!(pt2["aud"], r2.issuer);
        assert_eq!(
            pt2["cnf"]["jwk"]["x"], r1_agent.jwk.x,
            "bound to the intermediary's key"
        );
        assert_eq!(
            pt2["sub"],
            app.keys.derive_sub(&alice.id, &r2.issuer),
            "Alice's directed sub at R2"
        );
        // The intermediary is not bound to Alice.
        assert!(app
            .store
            .binding(&r1.issuer, &format!("aauth:svc@{r1_domain}"))
            .unwrap()
            .is_none());
        // 3. R2 challenges R1 → resource token → R1 exchanges it with the upstream token.
        let rt2 = r2.mint(
            UI_ISSUER,
            pt2["sub"].as_str().unwrap(),
            pt2["jti"].as_str().unwrap(),
            &r1_agent.jwk.thumbprint().unwrap(),
            "docs.read",
            300,
            serde_json::json!({}),
        );
        let (status, body, headers) = call(
            &app,
            Method::POST,
            "/token",
            r1_req(
                "/token",
                serde_json::json!({ "resource_token": rt2, "upstream_token": at1 }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let (pid3, code3) = pending_and_code(&headers);
        decide(&app, &sid, &code3, "approve").await;
        let path = format!("/pending/{pid3}");
        let mut get_ctx = AgentReq {
            method: Method::GET,
            authority: UI_AUTHORITY.into(),
            path: path.clone(),
            body: vec![],
            cover_body: false,
            digest_override: None,
            created: None,
        }
        .into_ctx(&sigkey::serialize_jwt(&r1_token), &r1_agent.key);
        get_ctx.method = "GET".into();
        let (status, body, _) = call(&app, Method::GET, &path, get_ctx).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let at2 = jwt::decode(body["auth_token"].as_str().unwrap())
            .unwrap()
            .payload;
        assert_eq!(at2["aud"], r2.issuer);
        assert_eq!(at2["sub"], pt2["sub"]);
        assert_eq!(at2["cnf"]["jwk"]["x"], r1_agent.jwk.x);
        assert!(at2.get("act").is_none());
        // 4. Failure paths: an upstream token issued to someone else's
        //    intermediary (aud ≠ signer iss), one we never issued, one revoked.
        let stranger = spawn_mock_resource().await;
        let s_agent = new_agent();
        let s_token = stranger.mint_agent_token("svc", &s_agent.jwk, 3600);
        let ctx = AgentReq::post(
            "/person",
            serde_json::json!({ "resource": r2.issuer, "upstream_token": at1 }),
        )
        .authority(UI_AUTHORITY)
        .into_ctx(&sigkey::serialize_jwt(&s_token), &s_agent.key);
        let (status, body, _) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["detail"].as_str().unwrap().contains("upstream_token"));
        let (status, body, _) = call(
            &app,
            Method::POST,
            "/person",
            r1_req(
                "/person",
                serde_json::json!({ "resource": r2.issuer, "upstream_token": "x.y.z" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        app.store
            .mark_auth_token_revoked(jwt::decode(&at1).unwrap().payload["jti"].as_str().unwrap())
            .unwrap();
        // A fresh signature (later `created`): the same request bytes within a
        // second would be a replay to the signature layer.
        let ctx = AgentReq::post(
            "/person",
            serde_json::json!({ "resource": r2.issuer, "upstream_token": at1 }),
        )
        .authority(UI_AUTHORITY)
        .created(aauth_core::now_unix() + 2)
        .into_ctx(&sigkey::serialize_jwt(&r1_token), &r1_agent.key);
        let (status, body, _) = call(&app, Method::POST, "/person", ctx).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["detail"].as_str().unwrap().contains("revoked"));
    }
}

// ============================================================ OIDC person login
mod oidc_tests {
    use super::flow_support::{pending_and_code, poll, post_person};
    use super::ui_tests::{call_raw, get, post_form, UI_ISSUER};
    use super::*;
    use crate::oidc::OidcRuntime;
    use p256::ecdsa::signature::Signer as _;
    use sha2::Digest as _;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// An OpenID Connect provider in a box: discovery, a JWKS, and a token
    /// endpoint that checks the client secret, spends the code once, and
    /// verifies the PKCE verifier against the challenge the authorization
    /// step recorded. The "browser visit" to the authorization endpoint is
    /// simulated by [`MockIdp::authorize`], which does what a real IdP does
    /// after the person authenticates: mint a code bound to the request's
    /// nonce and code_challenge.
    struct MockIdp {
        issuer: String,
        client_id: String,
        secret: String,
        /// code → (nonce, code_challenge)
        codes: Arc<StdMutex<HashMap<String, (String, String)>>>,
        /// Claims minted into every ID token (over the standard ones).
        claims: Arc<StdMutex<serde_json::Value>>,
        /// (`aud` minted as an array, with `azp` naming us).
        aud_array: Arc<StdMutex<(bool, bool)>>,
        /// Sabotage knobs.
        nonce_override: Arc<StdMutex<Option<String>>>,
        kid_override: Arc<StdMutex<Option<String>>>,
        alg_none: Arc<StdMutex<bool>>,
        /// Flip a byte of the signature: the token must then fail for that
        /// reason and no other, so a test cannot pass by skipping the check.
        tamper: Arc<StdMutex<bool>>,
        _handle: tokio::task::JoinHandle<()>,
    }

    /// How the mock signs and what its documents look like: a generic ES256
    /// provider, or Okta's shapes (org authorization server, RS256, the
    /// exact discovery and JWKS fields Okta emits) with our own RSA key.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Flavour {
        Es256,
        Okta,
    }

    /// A 2048-bit RSA key generated for these tests only (PKCS#8 DER,
    /// standard base64) and its public components as a JWK carries them.
    const TEST_RSA_PKCS8_B64: &str = "MIIEowIBAAKCAQEAo4C1RClQU6KcxDCQX6LQKkN5M0R+zfACgTI6FFRrTRBRqtNkzQOmON1wHV5NdWPEQbOg7tsC25PR5RJTHXoTZlicQ/ZTiKgFKlSPODxGE86Mve2YFkrY3FUHwGKft1peWvL8tv8wBcGbCr/scn7uIzQm4Io8wcZGDKyNBbBa90bljVnoSkfWcyQoeTmZXyoaV7Bdx7PMmE7pqcO+jWuE5Ic6sc6vqxuBmB7YSMmmhwRSXym4/noH9S+vB12AxXzWvuR2vvAZefD+IGeXsptdSAXu13aNJ1dEzdHQt4Jg5bTTdwJViYISrSi2XET5A2ky3prWMvtsMf/CQhYMTif0nQIDAQABAoIBAAU5s1Fa2qjZnRX+EVclHm8DWgfD7COLxKC5aLbGnelIGLwTZnjQ4YqWtSMTJPmX9yk8YuvPTw+ScVZXWBWslZsjQNdBM5k9+XBJZIxhDMJMSx40zjQEL1sXUpiY7k7PUg2pD1+P10qPzfMxgA6GtPimDYoGkPuGaS21hApHARk++zoycuTVkPTn3OAR+5OS2D/xc5klk9mZLZ/k78Sdau5/IMqp0vzYzvEmxqxcRSxUwP4xUhpTe2aB/8py5OqxFQ/3tgZrGXI873+Ls9MsJvvWigMOvCOlTBz/Aie6CFSb0Jv5EYyKUrbdtO0XcHSrCxA0WcG9eF1T9dCU6zGycscCgYEAzsEPgDGgjU29panwZk+LX1v64ynyugf6KwUzPzrol7VAjIVxH+KL5vtzA+zKVHRgfkJCAhpSzJxGN+iBYktHywAT6RWM+y6TwNToBfWGqNc6BcLNJpmmGdZ5t5Xrwoiew5ndmkHwqodU/bimCBVxI5Tfi/Wx8n9rEv3C5Ve4i08CgYEAynJfaw5kNbc8nVc3pGrugPPNAJALJCSGdoVzY1OWuKNxi8rggdQyfpD42kVFOqeEzhG+jLSolERj9ZGLltu+JrCaaJyZdr50EQ1C5oRPajCv0SyGyXKwKIwEDNGhXg5bCAGbGophKHILPJsFPNFt+nrBGbR9WNgAxmxi0wqGFlMCgYB5ncqWZ5q/Q5lolzvXkray0xITCZvDnemj4J0ydl5WzsE3Z08RqFsO9Z3EE0c4wnP4ENVvEzjdLpeHT3a78Pg8CsGre4fAQLec2B/bUX9yVZfFx76RFBRGYoiaWs+hUGfDOwDFOkBsrspprHHNk39HpMySMWYI9LZxJ1+7NAxTtQKBgD0sIC7+M0OT8cntX8/by+PFR43C+MrcCpFns70wtdtm79l43Sv9zaA2+CskQU3+7n9CF1z2/fWHUNkUOKTGE4gnVxEDONALrpC0fCGhm0mQGqBPHw9iC17FKDgjY+pC1jjuG0sCw2bwRvryMLv24I+OZij5Q+MDqgBLIfV5OZknAoGBAJKj8E7qY6BCCf7jx3RbXG2VQ356pYreXL9oOARwwPBuXTT9S3Z7t7W2bzwgsHKdoQ8zePUb3cifQgz9y7gQEQ0AwlyC7ilwScswNSNbISLFJ6+KNnNgEQXiBBdjD92plWtB77O4oII+iKdZt2bK9lKE9RhHx4/0yoGIiJgVl7Tv";
    const TEST_RSA_N: &str = "o4C1RClQU6KcxDCQX6LQKkN5M0R-zfACgTI6FFRrTRBRqtNkzQOmON1wHV5NdWPEQbOg7tsC25PR5RJTHXoTZlicQ_ZTiKgFKlSPODxGE86Mve2YFkrY3FUHwGKft1peWvL8tv8wBcGbCr_scn7uIzQm4Io8wcZGDKyNBbBa90bljVnoSkfWcyQoeTmZXyoaV7Bdx7PMmE7pqcO-jWuE5Ic6sc6vqxuBmB7YSMmmhwRSXym4_noH9S-vB12AxXzWvuR2vvAZefD-IGeXsptdSAXu13aNJ1dEzdHQt4Jg5bTTdwJViYISrSi2XET5A2ky3prWMvtsMf_CQhYMTif0nQ";
    const TEST_RSA_E: &str = "AQAB";

    enum Signer {
        Es256(p256::ecdsa::SigningKey),
        Rs256(Arc<ring::signature::RsaKeyPair>),
    }

    impl Signer {
        fn jwk(&self, kid: &str) -> serde_json::Value {
            match self {
                Signer::Es256(key) => {
                    let point = key.verifying_key().to_encoded_point(false);
                    serde_json::json!({
                        "kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig",
                        "x": aauth_core::b64::encode(point.x().unwrap()),
                        "y": aauth_core::b64::encode(point.y().unwrap()),
                    })
                }
                Signer::Rs256(_) => serde_json::json!({
                    "kty": "RSA", "alg": "RS256", "kid": kid, "use": "sig",
                    "e": TEST_RSA_E, "n": TEST_RSA_N,
                }),
            }
        }
        fn alg(&self) -> &'static str {
            match self {
                Signer::Es256(_) => "ES256",
                Signer::Rs256(_) => "RS256",
            }
        }
        fn sign(&self, header: &serde_json::Value, payload: &serde_json::Value) -> String {
            let h = aauth_core::b64::encode(header.to_string().as_bytes());
            let p = aauth_core::b64::encode(payload.to_string().as_bytes());
            let input = format!("{h}.{p}");
            let sig = match self {
                Signer::Es256(key) => {
                    let sig: p256::ecdsa::Signature = key.sign(input.as_bytes());
                    sig.to_bytes().to_vec()
                }
                Signer::Rs256(pair) => {
                    let mut out = vec![0u8; pair.public().modulus_len()];
                    pair.sign(
                        &ring::signature::RSA_PKCS1_SHA256,
                        &ring::rand::SystemRandom::new(),
                        input.as_bytes(),
                        &mut out,
                    )
                    .unwrap();
                    out
                }
            };
            format!("{input}.{}", aauth_core::b64::encode(&sig))
        }
    }

    /// The token endpoint's behaviour, shared by every connection.
    #[derive(Clone)]
    struct IdpState {
        issuer: String,
        client_id: String,
        secret: String,
        signer: Arc<Signer>,
        kid: String,
        codes: Arc<StdMutex<HashMap<String, (String, String)>>>,
        claims: Arc<StdMutex<serde_json::Value>>,
        nonce_override: Arc<StdMutex<Option<String>>>,
        kid_override: Arc<StdMutex<Option<String>>>,
        alg_none: Arc<StdMutex<bool>>,
        tamper: Arc<StdMutex<bool>>,
        aud_array: Arc<StdMutex<(bool, bool)>>,
        /// (discovery, token, jwks) paths.
        paths: (&'static str, &'static str, &'static str),
        disc_s: String,
        jwks_s: String,
    }

    impl IdpState {
        fn handle(
            &self,
            method: Method,
            path: &str,
            auth: Option<&str>,
            body: &[u8],
        ) -> (u16, String) {
            let (disc_path, token_path, jwks_path) = self.paths;
            match (method, path) {
                (Method::GET, p) if p == disc_path => (200, self.disc_s.clone()),
                (Method::GET, p) if p == jwks_path => (200, self.jwks_s.clone()),
                (Method::POST, p) if p == token_path => self.token(auth, body),
                _ => (404, "{}".to_string()),
            }
        }

        fn token(&self, auth: Option<&str>, body: &[u8]) -> (u16, String) {
            let form = crate::ui::parse_form(body);
            let expected = format!(
                "Basic {}",
                aauth_core::b64::encode_std(
                    format!("{}:{}", self.client_id, self.secret).as_bytes()
                )
            );
            if auth != Some(expected.as_str()) {
                return (
                    401,
                    serde_json::json!({"error":"invalid_client"}).to_string(),
                );
            }
            if form.get("grant_type").map(String::as_str) != Some("authorization_code") {
                return (
                    400,
                    serde_json::json!({"error":"unsupported_grant_type"}).to_string(),
                );
            }
            let code = form.get("code").cloned().unwrap_or_default();
            let Some((nonce, challenge)) = self.codes.lock().unwrap().remove(&code) else {
                return (
                    400,
                    serde_json::json!({"error":"invalid_grant"}).to_string(),
                );
            };
            let verifier = form.get("code_verifier").cloned().unwrap_or_default();
            let got = aauth_core::b64::encode(&sha2::Sha256::digest(verifier.as_bytes()));
            if got != challenge {
                return (
                    400,
                    serde_json::json!({"error":"invalid_grant","error_description":"pkce"})
                        .to_string(),
                );
            }
            let now = aauth_core::now_unix();
            let mut payload = self.claims.lock().unwrap().clone();
            payload["iss"] = self.issuer.clone().into();
            let (as_array, with_azp) = *self.aud_array.lock().unwrap();
            if as_array {
                payload["aud"] = serde_json::json!([self.client_id, "another-client"]);
                if with_azp {
                    payload["azp"] = self.client_id.clone().into();
                }
            } else {
                payload["aud"] = self.client_id.clone().into();
            }
            payload["iat"] = now.into();
            payload["exp"] = (now + 300).into();
            payload["nonce"] = self
                .nonce_override
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(nonce)
                .into();
            let use_kid = self
                .kid_override
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(self.kid.clone());
            let id_token = if *self.alg_none.lock().unwrap() {
                let h = aauth_core::b64::encode(br#"{"alg":"none","typ":"JWT"}"#);
                let p = aauth_core::b64::encode(payload.to_string().as_bytes());
                format!("{h}.{p}.")
            } else {
                // Okta's header carries no typ; a JWT header need not.
                let t = self.signer.sign(
                    &serde_json::json!({"alg": self.signer.alg(), "kid": use_kid}),
                    &payload,
                );
                if *self.tamper.lock().unwrap() {
                    let mut chars: Vec<char> = t.chars().collect();
                    let last = chars.len() - 1;
                    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
                    chars.into_iter().collect()
                } else {
                    t
                }
            };
            (200, serde_json::json!({ "access_token": "at", "token_type": "Bearer", "id_token": id_token }).to_string())
        }
    }

    async fn spawn_mock_idp() -> MockIdp {
        spawn_idp(Flavour::Es256).await
    }

    async fn spawn_idp(flavour: Flavour) -> MockIdp {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Okta's *custom* authorization server (the shape most orgs run
        // for OIDC apps) has a path in its issuer; discovery is the issuer
        // plus the well-known suffix, and every endpoint lives under it.
        let issuer = match flavour {
            Flavour::Es256 => format!("http://127.0.0.1:{port}"),
            Flavour::Okta => format!("http://127.0.0.1:{port}/oauth2/default"),
        };
        let signer = Arc::new(match flavour {
            Flavour::Es256 => Signer::Es256(p256::ecdsa::SigningKey::random(
                &mut p256::elliptic_curve::rand_core::OsRng,
            )),
            Flavour::Okta => Signer::Rs256(Arc::new(
                ring::signature::RsaKeyPair::from_der(
                    &aauth_core::b64::decode_std(TEST_RSA_PKCS8_B64).unwrap(),
                )
                .unwrap(),
            )),
        });
        let (kid, client_id) = match flavour {
            Flavour::Es256 => ("idp-key-1", "psd-client"),
            Flavour::Okta => (
                "eq5U0N7l0Bp5s5DBmzn3XLzKX_wDlaGDNfCPMs2Rl4o",
                "0oa1b2c3d4e5f6g7h8i9",
            ),
        };
        let claims = match flavour {
            Flavour::Es256 => serde_json::json!({
                "sub": "user-1", "email": "alice@acme.example", "name": "Alice Example",
                "groups": ["everyone", "psd-users"], "org": "acme"
            }),
            // What an Okta org authorization server puts in an ID token,
            // with a Groups claim filter configured on the application.
            Flavour::Okta => serde_json::json!({
                "sub": "00u1a2b3c4d5e6f7g8h9", "name": "Alice Example",
                "email": "alice@acme.example", "ver": 1,
                "jti": "ID.k1QO0Ai_x-6yQ7X6t3Yb9Q6z2y5", "amr": ["pwd", "mfa"],
                "idp": "00o9z8y7x6w5v4u3t2s1", "preferred_username": "alice@acme.example",
                "auth_time": aauth_core::now_unix(), "at_hash": "F0zY9WsRJHYCbtSMngjBiw",
                "groups": ["Everyone", "psd-users"], "org": "acme"
            }),
        };
        let disc_s = match flavour {
            Flavour::Es256 => serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "id_token_signing_alg_values_supported": ["ES256"],
            }),
            // Okta's org-AS discovery document, field for field (paths kept;
            // only the host is ours).
            Flavour::Okta => serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/v1/authorize"),
                "token_endpoint": format!("{issuer}/v1/token"),
                "userinfo_endpoint": format!("{issuer}/v1/userinfo"),
                "registration_endpoint": format!("{issuer}/v1/clients"),
                "jwks_uri": format!("{issuer}/v1/keys"),
                "response_types_supported": ["code", "id_token", "code id_token", "code token", "id_token token", "code id_token token"],
                "response_modes_supported": ["query", "fragment", "form_post", "okta_post_message"],
                "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "password", "urn:ietf:params:oauth:grant-type:device_code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "scopes_supported": ["openid", "email", "profile", "address", "phone", "offline_access", "groups"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none"],
                "claims_supported": ["iss", "ver", "sub", "aud", "iat", "exp", "jti", "auth_time", "amr", "idp", "nonce", "name", "nickname", "preferred_username", "given_name", "middle_name", "family_name", "email", "email_verified", "profile", "zoneinfo", "locale", "address", "phone_number", "picture", "website", "gender", "birthdate", "updated_at", "at_hash", "c_hash"],
                "code_challenge_methods_supported": ["S256"],
                "introspection_endpoint": format!("{issuer}/v1/introspect"),
                "revocation_endpoint": format!("{issuer}/v1/revoke"),
                "end_session_endpoint": format!("{issuer}/v1/logout"),
                "request_parameter_supported": true,
                "request_object_signing_alg_values_supported": ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                "device_authorization_endpoint": format!("{issuer}/v1/device/authorize"),
                "pushed_authorization_request_endpoint": format!("{issuer}/v1/par"),
                "backchannel_token_delivery_modes_supported": ["poll"],
                "backchannel_authentication_request_signing_alg_values_supported": ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                "dpop_signing_alg_values_supported": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            }),
        }
        .to_string();
        let paths = match flavour {
            Flavour::Es256 => ("/.well-known/openid-configuration", "/token", "/jwks"),
            Flavour::Okta => (
                "/oauth2/default/.well-known/openid-configuration",
                "/oauth2/default/v1/token",
                "/oauth2/default/v1/keys",
            ),
        };
        let st = IdpState {
            issuer: issuer.clone(),
            client_id: client_id.to_string(),
            secret: "s3cret".to_string(),
            jwks_s: serde_json::json!({ "keys": [signer.jwk(kid)] }).to_string(),
            signer,
            kid: kid.to_string(),
            codes: Default::default(),
            claims: Arc::new(StdMutex::new(claims)),
            nonce_override: Default::default(),
            kid_override: Default::default(),
            alg_none: Arc::new(StdMutex::new(false)),
            tamper: Arc::new(StdMutex::new(false)),
            aud_array: Arc::new(StdMutex::new((false, true))),
            paths,
            disc_s,
        };
        let out = MockIdp {
            issuer,
            client_id: st.client_id.clone(),
            secret: st.secret.clone(),
            codes: st.codes.clone(),
            claims: st.claims.clone(),
            aud_array: st.aud_array.clone(),
            nonce_override: st.nonce_override.clone(),
            kid_override: st.kid_override.clone(),
            alg_none: st.alg_none.clone(),
            tamper: st.tamper.clone(),
            _handle: tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    let st = st.clone();
                    tokio::spawn(async move {
                        let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let st = st.clone();
                            async move {
                                let path = req.uri().path().to_string();
                                let method = req.method().clone();
                                let auth = req
                                    .headers()
                                    .get("authorization")
                                    .and_then(|v| v.to_str().ok())
                                    .map(String::from);
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let (status, out) =
                                    st.handle(method, &path, auth.as_deref(), &body);
                                Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder()
                                        .status(status)
                                        .header("content-type", "application/json")
                                        .body(http_body_util::Full::new(hyper::body::Bytes::from(
                                            out,
                                        )))
                                        .unwrap(),
                                )
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            }),
        };
        out
    }

    impl MockIdp {
        /// What the IdP does after the person signs in: check the request,
        /// mint a code bound to its nonce and PKCE challenge, and hand back
        /// (code, state) for the redirect to the callback.
        fn authorize(&self, location: &str) -> (String, String) {
            let (base, query) = location.split_once('?').unwrap();
            assert!(
                base == format!("{}/authorize", self.issuer)
                    || base == format!("{}/v1/authorize", self.issuer),
                "{base}"
            );
            let q: HashMap<String, String> = query
                .split('&')
                .map(|kv| {
                    let (k, v) = kv.split_once('=').unwrap();
                    (
                        k.to_string(),
                        crate::ui::parse_form(format!("x={v}").as_bytes())
                            .remove("x")
                            .unwrap(),
                    )
                })
                .collect();
            assert_eq!(q["response_type"], "code");
            assert_eq!(q["client_id"], self.client_id);
            assert_eq!(
                q["redirect_uri"],
                format!("{UI_ISSUER}/login/oidc/callback")
            );
            assert!(
                q["scope"].split(' ').any(|s| s == "openid"),
                "{}",
                q["scope"]
            );
            assert_eq!(q["code_challenge_method"], "S256");
            assert!(q["state"].len() >= 32 && q["nonce"].len() >= 32);
            let code = format!("code-{}", aauth_core::rand_id(12));
            self.codes.lock().unwrap().insert(
                code.clone(),
                (q["nonce"].clone(), q["code_challenge"].clone()),
            );
            (code, q["state"].clone())
        }
    }

    fn secret_file(secret: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("psd-oidc-secret-{}", aauth_core::rand_id(8)));
        std::fs::write(&p, format!("{secret}\n")).unwrap();
        p
    }

    fn oidc_config(idp: &MockIdp, extra: serde_json::Value) -> Config {
        let mut oidc = serde_json::json!({
            "issuer": idp.issuer, "client_id": idp.client_id,
            "client_secret_file": secret_file(&idp.secret).to_string_lossy(),
            "required_claims": { "groups": "psd-users" },
            "tenant_claim": "org",
        });
        if let Some(obj) = extra.as_object() {
            for (k, v) in obj {
                oidc[k] = v.clone();
            }
        }
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "issuer": UI_ISSUER,
            "listen": "127.0.0.1:0",
            "storage": { "backend": "sqlite", "path": ":memory:" },
            "insecure_dev_mode": true,
            "metadata": { "name": "Test PS" },
            "person_auth": { "method": "oidc", "oidc": oidc },
        }))
        .unwrap();
        cfg.validate().unwrap();
        cfg
    }

    async fn oidc_app(idp: &MockIdp, extra: serde_json::Value) -> Arc<App> {
        let cfg = oidc_config(idp, extra);
        let egress = crate::httpc::EgressPolicy::from_config(true);
        let rt = OidcRuntime::discover(&cfg, &egress)
            .await
            .expect("discovery");
        let store = crate::store::Store::open(":memory:").unwrap();
        App::build_with(cfg, KeySet::generate(), Audit::quiet(), store, Some(rt)).unwrap()
    }

    /// A GET with arbitrary cookies (name, value).
    fn get_with_cookies(path: &str, cookies: &[(&str, &str)]) -> ReqCtx {
        let mut ctx = get(path, None);
        if !cookies.is_empty() {
            let c = cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            ctx.headers.push(("cookie".into(), c));
        }
        ctx
    }

    fn cookie_named(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
        headers.get_all("set-cookie").iter().find_map(|v| {
            let s = v.to_str().ok()?;
            let first = s.split(';').next()?;
            first.strip_prefix(&format!("{name}=")).map(String::from)
        })
    }

    fn set_cookie_line(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
        headers.get_all("set-cookie").iter().find_map(|v| {
            let s = v.to_str().ok()?;
            s.starts_with(&format!("{name}=")).then(|| s.to_string())
        })
    }

    /// Start a sign-in: returns (authorization URL, psd_oidc cookie value).
    async fn start(app: &Arc<App>, path: &str) -> (String, String) {
        let (status, body, headers) =
            call_raw(app, Method::GET, "/login/oidc", get(path, None)).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        let loc = hdr(&headers, "location").unwrap().to_string();
        let line = set_cookie_line(&headers, "psd_oidc").expect("psd_oidc cookie");
        assert!(
            line.contains("HttpOnly")
                && line.contains("SameSite=Lax")
                && line.contains("Path=/login/oidc"),
            "{line}"
        );
        assert!(!line.contains("Secure"), "http issuer in dev: {line}");
        let cookie = cookie_named(&headers, "psd_oidc").unwrap();
        (loc, cookie)
    }

    async fn callback(
        app: &Arc<App>,
        code: &str,
        state: &str,
        oidc_cookie: Option<&str>,
        session: Option<&str>,
    ) -> (StatusCode, String, hyper::HeaderMap) {
        let path = format!(
            "/login/oidc/callback?code={}&state={}",
            crate::oidc::form_encode(code),
            crate::oidc::form_encode(state)
        );
        let mut cookies: Vec<(&str, &str)> = Vec::new();
        if let Some(c) = oidc_cookie {
            cookies.push(("psd_oidc", c));
        }
        if let Some(s) = session {
            cookies.push((crate::ui::SESSION_COOKIE, s));
        }
        call_raw(
            app,
            Method::GET,
            "/login/oidc/callback",
            get_with_cookies(&path, &cookies),
        )
        .await
    }

    fn actions(app: &Arc<App>, person: Option<&str>) -> Vec<(String, serde_json::Value)> {
        app.store
            .recent_audit(person, 50)
            .unwrap()
            .into_iter()
            .map(|r| (r.action, r.detail))
            .collect()
    }

    #[tokio::test]
    async fn discovery_checks_the_issuer_and_the_secret_file() {
        let idp = spawn_mock_idp().await;
        let egress = crate::httpc::EgressPolicy::from_config(true);
        // Configured issuer that is not what the document declares.
        let mut cfg = oidc_config(&idp, serde_json::json!({}));
        cfg.person_auth.oidc.as_mut().unwrap().issuer = format!("{}/tenant", idp.issuer);
        let err = OidcRuntime::discover(&cfg, &egress).await.unwrap_err();
        assert!(err.contains("discovery"), "{err}");
        // Missing secret file.
        let mut cfg = oidc_config(&idp, serde_json::json!({}));
        cfg.person_auth.oidc.as_mut().unwrap().client_secret_file =
            "/nonexistent/psd-secret".into();
        let err = OidcRuntime::discover(&cfg, &egress).await.unwrap_err();
        assert!(err.contains("client_secret_file"), "{err}");
        // Good: endpoints taken from the document, redirect_uri fixed.
        let cfg = oidc_config(&idp, serde_json::json!({}));
        let rt = OidcRuntime::discover(&cfg, &egress).await.unwrap();
        assert_eq!(rt.token_endpoint, format!("{}/token", idp.issuer));
        assert_eq!(rt.redirect_uri, format!("{UI_ISSUER}/login/oidc/callback"));
        assert!(!format!("{rt:?}").contains("s3cret"));
    }

    #[tokio::test]
    async fn sso_sign_in_provisions_links_and_issues_tenant() {
        let idp = spawn_mock_idp().await;
        let app = oidc_app(&idp, serde_json::json!({})).await;
        // The login page offers both.
        let (status, page, _) = call_raw(&app, Method::GET, "/login", get("/login", None)).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(
            page.contains("/login/oidc?next=") && page.contains("passkey-get"),
            "{page}"
        );

        let (loc, cookie) = start(&app, "/login/oidc?next=/activity").await;
        let (code, state) = idp.authorize(&loc);
        let (status, body, headers) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        assert_eq!(hdr(&headers, "location"), Some("/activity"));
        let sid = cookie_named(&headers, crate::ui::SESSION_COOKIE).expect("session cookie");
        // The oidc cookie is cleared.
        assert!(set_cookie_line(&headers, "psd_oidc")
            .unwrap()
            .contains("Max-Age=0"));

        // Provisioned just in time, keyed on (iss, sub), display name from `name`.
        let persons = app.store.list_persons().unwrap();
        assert_eq!(persons.len(), 1);
        let p = &persons[0];
        assert_eq!(p.display_name, "Alice Example");
        assert_eq!(p.tenant.as_deref(), Some("acme"));
        let id = app.store.identity(&idp.issuer, "user-1").unwrap().unwrap();
        assert_eq!(id.person_id, p.id);
        assert_eq!(id.email.as_deref(), Some("alice@acme.example"));
        assert!(id.last_login_at.is_some());
        // The session works and the audit says how they got in.
        let (status, dash, _) = call_raw(&app, Method::GET, "/", get("/", Some(&sid))).await;
        assert_eq!(status, StatusCode::OK, "{dash}");
        let acts = actions(&app, Some(&p.id));
        assert!(
            acts.iter().any(|(a, d)| a == "signed_in"
                && d["method"] == "oidc"
                && d["idp_sub"] == "user-1"),
            "{acts:?}"
        );
        assert!(
            acts.iter()
                .any(|(a, d)| a == "person_provisioned" && d["via"] == "oidc"),
            "{acts:?}"
        );
        // Sign-in methods page shows the linked identity, no connect button.
        let (status, page, _) =
            call_raw(&app, Method::GET, "/passkeys", get("/passkeys", Some(&sid))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            page.contains("alice@acme.example") && !page.contains("/passkeys/oidc/link"),
            "{page}"
        );

        // Second sign-in: same person, no new row; email refreshed.
        idp.claims.lock().unwrap()["email"] = "alice.new@acme.example".into();
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, _, headers) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(hdr(&headers, "location"), Some("/"));
        assert_eq!(app.store.list_persons().unwrap().len(), 1);
        assert_eq!(
            app.store
                .identity(&idp.issuer, "user-1")
                .unwrap()
                .unwrap()
                .email
                .as_deref(),
            Some("alice.new@acme.example")
        );

        // The tenant lands in person tokens the person's agents obtain.
        let agent = new_agent();
        let issued = crate::issue::person_token(
            &app,
            &crate::issue::PersonTokenRequest {
                person_id: &p.id,
                agent_iss: "https://ap.example",
                agent_sub: "aauth:a@ap.example",
                cnf_jwk: &agent.jwk,
                audience: "https://calendar.example",
                agent_token_exp: aauth_core::now_unix() + 600,
                mission_expires_at: None,
                mission_s256: None,
                tenant: None,
            },
        )
        .unwrap();
        let payload = jwt::decode(&issued.token).unwrap().payload;
        assert_eq!(payload["tenant"], "acme");
        assert_eq!(
            app.store
                .person_token_record(&issued.jti)
                .unwrap()
                .unwrap()
                .tenant
                .as_deref(),
            Some("acme")
        );
        // An org move is reflected at the next sign-in.
        idp.claims.lock().unwrap()["org"] = "acme-emea".into();
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(
            app.store
                .get_person(&p.id)
                .unwrap()
                .unwrap()
                .tenant
                .as_deref(),
            Some("acme-emea")
        );
    }

    #[tokio::test]
    async fn callback_binding_state_cookie_and_single_use() {
        let idp = spawn_mock_idp().await;
        let app = oidc_app(&idp, serde_json::json!({})).await;
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        // No cookie: the attempt is not this browser's.
        let (status, page, _) = callback(&app, &code, &state, None, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{page}");
        assert!(page.contains("Sign-in attempt not found"));
        // Wrong state with the right cookie: refused, and the row is spent.
        let (status, page, _) = callback(&app, &code, "not-the-state", Some(&cookie), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{page}");
        assert!(page.contains("does not match"));
        let (status, page, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{page}");
        assert!(
            page.contains("Sign-in attempt not found"),
            "spent on first presentation"
        );
        assert!(app.store.list_persons().unwrap().is_empty());

        // The lure: attacker starts an attempt, gets a code for *their*
        // identity, and sends the victim (who has an attempt of their own
        // open) to the callback URL. The victim's cookie names the victim's
        // row; the attacker's state does not match it.
        let (attacker_loc, _attacker_cookie) = start(&app, "/login/oidc").await;
        let (a_code, a_state) = idp.authorize(&attacker_loc);
        let (_victim_loc, victim_cookie) = start(&app, "/login/oidc").await;
        let (status, _, headers) =
            callback(&app, &a_code, &a_state, Some(&victim_cookie), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(cookie_named(&headers, crate::ui::SESSION_COOKIE).is_none());
        assert!(app.store.list_persons().unwrap().is_empty());

        // A completed sign-in cannot be replayed: same code+state again.
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, _, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let (status, _, headers) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(cookie_named(&headers, crate::ui::SESSION_COOKIE).is_none());
        // Provider error → shown, audited, nothing created.
        let (_loc, cookie) = start(&app, "/login/oidc").await;
        let path =
            "/login/oidc/callback?error=access_denied&error_description=user%20cancelled&state=x";
        let (status, page, _) = call_raw(
            &app,
            Method::GET,
            "/login/oidc/callback",
            get_with_cookies(path, &[("psd_oidc", &cookie)]),
        )
        .await;
        // state does not match → refused before the error is even read; the
        // error path is reached only with the right state:
        assert_eq!(status, StatusCode::BAD_REQUEST, "{page}");
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (_code, state) = idp.authorize(&loc);
        let path = format!("/login/oidc/callback?error=access_denied&state={state}");
        let (status, page, _) = call_raw(
            &app,
            Method::GET,
            "/login/oidc/callback",
            get_with_cookies(&path, &[("psd_oidc", &cookie)]),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{page}");
        assert!(page.contains("access_denied"));
    }

    #[tokio::test]
    async fn id_token_must_carry_this_attempts_nonce_and_a_known_key() {
        let idp = spawn_mock_idp().await;
        let app = oidc_app(&idp, serde_json::json!({})).await;
        // Nonce from another attempt.
        *idp.nonce_override.lock().unwrap() = Some("some-other-nonce".into());
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, page, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{page}");
        assert!(page.contains("could not be verified"));
        assert!(app.store.list_persons().unwrap().is_empty());
        *idp.nonce_override.lock().unwrap() = None;
        // alg=none.
        *idp.alg_none.lock().unwrap() = true;
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, _, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        *idp.alg_none.lock().unwrap() = false;
        // A kid the provider does not publish (its keys were fetched at
        // startup, within the floor, so that set is authoritative).
        *idp.kid_override.lock().unwrap() = Some("rotated-away".into());
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, page, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{page}");
        *idp.kid_override.lock().unwrap() = None;
        assert!(app.store.list_persons().unwrap().is_empty());
        // Sanity: the honest path still works afterwards.
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, _, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn required_claims_gate_and_provisioning_switch() {
        let idp = spawn_mock_idp().await;
        let app = oidc_app(&idp, serde_json::json!({})).await;
        idp.claims.lock().unwrap()["groups"] = serde_json::json!(["everyone"]);
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, page, headers) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{page}");
        assert!(page.contains("not permitted"));
        assert!(cookie_named(&headers, crate::ui::SESSION_COOKIE).is_none());
        assert!(
            app.store.list_persons().unwrap().is_empty(),
            "nothing provisioned"
        );
        assert!(app.store.identity(&idp.issuer, "user-1").unwrap().is_none());
        // An empty groups array never satisfies the gate.
        idp.claims.lock().unwrap()["groups"] = serde_json::json!([]);
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, _, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        idp.claims.lock().unwrap()["groups"] = serde_json::json!(["psd-users"]);

        // provision: false — an unknown identity is refused even past the gate.
        let app2 = oidc_app(&idp, serde_json::json!({ "provision": false })).await;
        let (loc, cookie) = start(&app2, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, page, _) = callback(&app2, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{page}");
        assert!(page.contains("No account for this identity"));
        assert!(app2.store.list_persons().unwrap().is_empty());
    }

    #[tokio::test]
    async fn passkey_person_connects_sso_and_deactivation_ends_everything() {
        let idp = spawn_mock_idp().await;
        let app = oidc_app(&idp, serde_json::json!({})).await;
        // A passkey person with a session (created directly; the passkey
        // ceremony is covered elsewhere).
        let alice = app.store.create_person("Alice").unwrap();
        let (sid, csrf) = app.store.create_session(&alice.id, 3600).unwrap();
        // The sign-in-methods page offers to connect.
        let (status, page, _) =
            call_raw(&app, Method::GET, "/passkeys", get("/passkeys", Some(&sid))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("/passkeys/oidc/link"), "{page}");
        // Linking is a CSRF-protected POST.
        let (status, _, _) = call_raw(
            &app,
            Method::POST,
            "/passkeys/oidc/link",
            post_form("/passkeys/oidc/link", &[], Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "no csrf");
        let (status, _, headers) = call_raw(
            &app,
            Method::POST,
            "/passkeys/oidc/link",
            post_form("/passkeys/oidc/link", &[("csrf", &csrf)], Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let loc = hdr(&headers, "location").unwrap().to_string();
        let cookie = cookie_named(&headers, "psd_oidc").unwrap();
        let (code, state) = idp.authorize(&loc);
        let (status, _, headers) = callback(&app, &code, &state, Some(&cookie), Some(&sid)).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(hdr(&headers, "location"), Some("/passkeys"));
        assert!(
            cookie_named(&headers, crate::ui::SESSION_COOKIE).is_none(),
            "already signed in"
        );
        let id = app.store.identity(&idp.issuer, "user-1").unwrap().unwrap();
        assert_eq!(id.person_id, alice.id);
        assert_eq!(
            app.store.list_persons().unwrap().len(),
            1,
            "linked, not provisioned"
        );
        assert_eq!(
            app.store
                .get_person(&alice.id)
                .unwrap()
                .unwrap()
                .tenant
                .as_deref(),
            Some("acme")
        );
        // The identity now signs Alice in.
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, _, headers) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let sid2 = cookie_named(&headers, crate::ui::SESSION_COOKIE).unwrap();
        assert_eq!(
            app.store.get_session(&sid2).unwrap().unwrap().person_id,
            alice.id
        );
        // Another person cannot connect the same identity.
        let bob = app.store.create_person("Bob").unwrap();
        let (bsid, bcsrf) = app.store.create_session(&bob.id, 3600).unwrap();
        let (_, _, headers) = call_raw(
            &app,
            Method::POST,
            "/passkeys/oidc/link",
            post_form("/passkeys/oidc/link", &[("csrf", &bcsrf)], Some(&bsid)),
        )
        .await;
        let loc = hdr(&headers, "location").unwrap().to_string();
        let cookie = cookie_named(&headers, "psd_oidc").unwrap();
        let (code, state) = idp.authorize(&loc);
        let (status, page, _) = callback(&app, &code, &state, Some(&cookie), Some(&bsid)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{page}");
        assert_eq!(
            app.store
                .identity(&idp.issuer, "user-1")
                .unwrap()
                .unwrap()
                .person_id,
            alice.id
        );

        // Deactivation: sessions gone, logins refused (SSO and passkey-side).
        app.store
            .set_person_status(&alice.id, "deactivated")
            .unwrap();
        app.store.delete_sessions_for_person(&alice.id).unwrap();
        let (status, _, headers) = call_raw(&app, Method::GET, "/", get("/", Some(&sid2))).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(hdr(&headers, "location").unwrap().starts_with("/login"));
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, page, headers) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{page}");
        assert!(page.contains("deactivated"));
        assert!(cookie_named(&headers, crate::ui::SESSION_COOKIE).is_none());
        // Enrolment links for a deactivated person are dead too.
        let token = app.store.create_enrolment(&alice.id, 600).unwrap();
        let (status, _, _) = call_raw(
            &app,
            Method::GET,
            &format!("/enrol/{token}"),
            get(&format!("/enrol/{token}"), None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Okta-shaped fixture: the org authorization server's discovery
    /// document, an RS256 JWKS, and ID tokens with Okta's claims — signed
    /// with our own RSA key. It does not prove psd works against Okta; it
    /// pins the document shapes, which is where generic OIDC code breaks.
    #[tokio::test]
    async fn okta_shaped_provider_signs_in_and_explains_the_gate() {
        let idp = spawn_idp(Flavour::Okta).await;
        let app = oidc_app(&idp, serde_json::json!({ "required_claims": { "groups": "psd-users" }, "tenant_claim": "org" })).await;
        let rt = app.oidc.as_ref().unwrap();
        // The issuer carries a path (a custom authorization server); the
        // endpoints were taken from discovery under it.
        assert!(idp.issuer.ends_with("/oauth2/default"));
        assert_eq!(rt.token_endpoint, format!("{}/v1/token", idp.issuer));
        assert_eq!(rt.jwks_uri, format!("{}/v1/keys", idp.issuer));

        // Happy path over RS256 with a string aud.
        let (loc, cookie) = start(&app, "/login/oidc").await;
        assert!(loc.starts_with(&format!("{}/v1/authorize?", idp.issuer)));
        let (code, state) = idp.authorize(&loc);
        let (status, page, headers) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{page}");
        let sid = cookie_named(&headers, crate::ui::SESSION_COOKIE).unwrap();
        let person = app.store.get_session(&sid).unwrap().unwrap().person_id;
        assert_eq!(
            app.store
                .identity(&idp.issuer, "00u1a2b3c4d5e6f7g8h9")
                .unwrap()
                .unwrap()
                .person_id,
            person
        );
        assert_eq!(
            app.store.get_person(&person).unwrap().unwrap().display_name,
            "Alice Example"
        );

        // A tampered RS256 signature over the same route: refused for that
        // reason and no other (the fixture cannot pass by skipping the check).
        *idp.tamper.lock().unwrap() = true;
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, page, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{page}");
        assert!(page.contains("could not be verified"), "{page}");
        *idp.tamper.lock().unwrap() = false;

        // Array aud with azp naming us: accepted. Without azp: refused.
        *idp.aud_array.lock().unwrap() = (true, true);
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, page, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{page}");
        *idp.aud_array.lock().unwrap() = (true, false);
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, _, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        *idp.aud_array.lock().unwrap() = (false, true);

        // The most predictable Okta failure: the groups claim is not in the
        // token until the application's Groups claim filter is configured.
        // The page and the audit say *that*, not "you are not in the group".
        idp.claims
            .lock()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("groups");
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, page, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{page}");
        assert!(
            page.contains(
                "ID token has no &#x27;groups&#x27; claim; the identity provider is not sending it"
            ),
            "{page}"
        );
        // Present but not permitted: the other message.
        idp.claims.lock().unwrap()["groups"] = serde_json::json!(["Everyone"]);
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, page, _) = callback(&app, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{page}");
        assert!(
            page.contains("&#x27;groups&#x27; does not include a permitted value"),
            "{page}"
        );
        // A namespaced claim path resolves as a literal key (Auth0 style).
        idp.claims.lock().unwrap()["https://acme.example/groups"] =
            serde_json::json!(["psd-users"]);
        let app2 = oidc_app(&idp, serde_json::json!({ "required_claims": { "https://acme.example/groups": "psd-users" } })).await;
        let (loc, cookie) = start(&app2, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (status, page, _) = callback(&app2, &code, &state, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{page}");
    }

    #[tokio::test]
    async fn sso_session_does_not_decide_consent() {
        // Authentication is not consent: an SSO session shortens the walk to
        // the button; it never presses it.
        let idp = spawn_mock_idp().await;
        let app = oidc_app(&idp, serde_json::json!({})).await;
        let (loc, cookie) = start(&app, "/login/oidc").await;
        let (code, state) = idp.authorize(&loc);
        let (_, _, headers) = callback(&app, &code, &state, Some(&cookie), None).await;
        let sid = cookie_named(&headers, crate::ui::SESSION_COOKIE).unwrap();
        // An agent asks; the request is deferred.
        let ap = spawn_mock_ap("ap-key-1", MockApOpts::default()).await;
        let agent = new_agent();
        let (status, _, headers) =
            post_person(&app, &ap, &agent, "agent-1", "https://calendar.example").await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (pending_id, code) = pending_and_code(&headers);
        // Opening the consent screen with the SSO session decides nothing.
        let (status, _, headers) = call_raw(
            &app,
            Method::GET,
            "/consent",
            get(&format!("/consent?code={code}"), Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let loc = hdr(&headers, "location").unwrap().to_string();
        let (status, page, _) = call_raw(&app, Method::GET, &loc, get(&loc, Some(&sid))).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.contains("Allow") && page.contains("csrf"), "{page}");
        let (status, _, _) = poll(&app, &ap, &agent, "agent-1", &pending_id).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "still pending after the page was viewed"
        );
        assert!(app.store.pending(&pending_id).unwrap().unwrap().is_open());
        // Only the explicit, CSRF-carrying POST decides.
        let csrf = app.store.get_session(&sid).unwrap().unwrap().csrf;
        let (status, page, _) = call_raw(
            &app,
            Method::POST,
            &loc,
            post_form(&loc, &[("csrf", &csrf), ("action", "approve")], Some(&sid)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let (status, body, _) = poll(&app, &ap, &agent, "agent-1", &pending_id).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let payload = jwt::decode(body["person_token"].as_str().unwrap())
            .unwrap()
            .payload;
        assert_eq!(payload["tenant"], "acme");
    }
}
