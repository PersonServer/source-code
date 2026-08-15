//! HTTP responses: RFC 9457 problem+json errors with the AAuth `error`
//! member, `Signature-Error` headers, and JSON success responses.
//!
//! Status discipline (AAuth -11, HTTP Message Signatures profile): every
//! signature failure is a `401` carrying `Signature-Error`; a `403` denies
//! *after* the signature verified and therefore MUST NOT carry
//! `Signature-Error`, `Accept-Signature-Scheme` or `Accept-Signature-Alg`.
//! [`ApiError::forbidden`] and [`ApiError::into_response`] enforce that.
//!
//! No `type` member is emitted: AAuth defines no problem type URIs and
//! receivers MUST NOT rely on `type` (§Error Response Format).
//!
//! Adapted from apd (MIT OR Apache-2.0).

use aauth_core::sig::{SigError, SigErrorCode};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Response, StatusCode};

pub type Body = Full<Bytes>;
pub type Resp = Response<Body>;

/// Header fields a `403` MUST NOT carry (sig-key draft, AAuth §Verification).
const SIGNATURE_HEADERS: [&str; 3] = [
    "signature-error",
    "accept-signature-scheme",
    "accept-signature-alg",
];

/// An API error that renders as problem+json (plus optional extra headers).
#[derive(Debug)]
#[allow(dead_code)] // constructors for later milestones' error codes
pub struct ApiError {
    pub status: StatusCode,
    pub error: String,
    pub detail: String,
    pub headers: Vec<(&'static str, String)>,
    /// Extra problem members (e.g. `termination_reason`, `mission_status`).
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[allow(dead_code)] // constructors for later milestones' error codes
impl ApiError {
    pub fn new(status: StatusCode, error: &str, detail: impl Into<String>) -> ApiError {
        ApiError {
            status,
            error: error.to_string(),
            detail: detail.into(),
            headers: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }

    pub fn bad_request(error: &str, detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, error, detail)
    }
    /// A `403`: authentication succeeded, authorization did not. Never carries
    /// signature headers (see module docs).
    pub fn forbidden(error: &str, detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::FORBIDDEN, error, detail)
    }
    pub fn not_found(error: &str, detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, error, detail)
    }
    pub fn too_many_requests(error: &str, detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::TOO_MANY_REQUESTS, error, detail)
    }
    pub fn server_error(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", detail)
    }

    /// `503 temporarily_unavailable` with `Retry-After`: this server could not
    /// do its part right now — typically a third party it must consult (an
    /// Agent Provider's JWKS, a resource's metadata) could not be fetched.
    /// Deliberately not a `401`: nothing is known against the caller's
    /// credential, and the draft's deferred-response state machine tells the
    /// agent to back off per `Retry-After` and retry a `503`.
    pub fn unavailable(detail: impl Into<String>, retry_after_secs: u64) -> ApiError {
        let mut e = ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            detail,
        );
        e.headers
            .push(("retry-after", retry_after_secs.to_string()));
        e
    }

    /// Attach an extra problem-details member.
    pub fn with_member(mut self, name: &str, value: serde_json::Value) -> ApiError {
        self.extra.insert(name.to_string(), value);
        self
    }

    /// A signature verification failure: 401 + `Signature-Error` header
    /// (the header is authoritative; the body mirrors it for humans).
    pub fn from_sig_error(err: SigError) -> ApiError {
        let mut header = format!("error={}", err.code.as_str());
        let mut headers: Vec<(&'static str, String)> = Vec::new();
        match err.code {
            SigErrorCode::UnsupportedAlgorithm => {
                // sig-key §5.4: an unsupported-algorithm response SHOULD carry an
                // `Accept-Signature-Alg` header naming the algorithms the server
                // accepts (fully-specified JOSE identifiers). psd is Ed25519-only.
                headers.push(("accept-signature-alg", aauth_core::jwk::ALG_ED25519.into()));
            }
            SigErrorCode::UnsupportedScheme => {
                // AAuth §Signature-Key Scheme Rejection: name what we accept.
                // A PS takes agent tokens (`jwt`) on its agent-facing endpoints.
                headers.push(("accept-signature-scheme", "jwt".into()));
            }
            SigErrorCode::InvalidInput => {
                if let Some(required) = &err.required_input {
                    let inner: Vec<String> = required
                        .iter()
                        .map(|c| aauth_core::sfv::serialize_string(c))
                        .collect();
                    header.push_str(&format!(", required_input=({})", inner.join(" ")));
                }
            }
            _ => {}
        }
        headers.push(("signature-error", header));
        ApiError {
            status: StatusCode::UNAUTHORIZED,
            error: err.code.as_str().to_string(),
            detail: err.detail,
            headers,
            extra: serde_json::Map::new(),
        }
    }

    pub fn into_response(self) -> Resp {
        let mut body = serde_json::Map::new();
        body.insert("error".into(), self.error.clone().into());
        body.insert("detail".into(), self.detail.into());
        body.insert("status".into(), self.status.as_u16().into());
        for (k, v) in self.extra {
            body.insert(k, v);
        }
        let mut builder = Response::builder()
            .status(self.status)
            .header("content-type", "application/problem+json")
            .header("cache-control", "no-store");
        for (name, value) in &self.headers {
            // A 403 MUST NOT carry signature negotiation headers.
            if self.status == StatusCode::FORBIDDEN && SIGNATURE_HEADERS.contains(name) {
                continue;
            }
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                builder = builder.header(n, v);
            }
        }
        builder
            .body(Full::new(Bytes::from(
                serde_json::Value::Object(body).to_string(),
            )))
            .unwrap()
    }
}

pub fn json_response(status: StatusCode, value: &serde_json::Value) -> Resp {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(value.to_string())))
        .unwrap()
}

pub fn json_ok(value: &serde_json::Value) -> Resp {
    json_response(StatusCode::OK, value)
}

/// Cacheable JSON (well-known documents).
pub fn json_cacheable(body: Bytes, max_age_secs: u32) -> Resp {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", format!("public, max-age={max_age_secs}"))
        .body(Full::new(body))
        .unwrap()
}

#[allow(dead_code)]
pub fn empty_status(status: StatusCode) -> Resp {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header<'a>(err: &'a ApiError, name: &str) -> Option<&'a str> {
        err.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn unsupported_algorithm_emits_accept_signature_alg() {
        let err =
            ApiError::from_sig_error(SigError::new(SigErrorCode::UnsupportedAlgorithm, "nope"));
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(header(&err, "accept-signature-alg"), Some("Ed25519"));
        assert_eq!(
            header(&err, "signature-error"),
            Some("error=unsupported_algorithm")
        );
    }

    #[test]
    fn unsupported_scheme_emits_accept_signature_scheme_jwt() {
        let err = ApiError::from_sig_error(SigError::new(SigErrorCode::UnsupportedScheme, "hwk"));
        assert_eq!(header(&err, "accept-signature-scheme"), Some("jwt"));
        assert_eq!(
            header(&err, "signature-error"),
            Some("error=unsupported_scheme")
        );
    }

    #[test]
    fn other_errors_have_no_accept_signature_headers() {
        let err = ApiError::from_sig_error(SigError::new(SigErrorCode::InvalidSignature, "x"));
        assert!(header(&err, "accept-signature-alg").is_none());
        assert!(header(&err, "accept-signature-scheme").is_none());
    }

    #[test]
    fn invalid_input_lists_required_components() {
        let mut e = SigError::new(SigErrorCode::InvalidInput, "missing");
        e.required_input = Some(vec!["content-digest".into(), "content-type".into()]);
        let err = ApiError::from_sig_error(e);
        assert_eq!(
            header(&err, "signature-error"),
            Some(r#"error=invalid_input, required_input=("content-digest" "content-type")"#)
        );
    }

    #[test]
    fn forbidden_never_carries_signature_headers() {
        // Even if a caller wrongly attaches one, the 403 response drops it.
        let mut err = ApiError::forbidden("denied", "no");
        err.headers
            .push(("signature-error", "error=invalid_signature".into()));
        err.headers.push(("accept-signature-alg", "Ed25519".into()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.headers().get("signature-error").is_none());
        assert!(resp.headers().get("accept-signature-alg").is_none());
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/problem+json"
        );
    }

    #[test]
    fn extra_members_render_in_body() {
        let err = ApiError::forbidden("mission_terminated", "ended")
            .with_member("termination_reason", "expired".into());
        let resp = err.into_response();
        let body = futures_body(resp);
        assert_eq!(body["error"], "mission_terminated");
        assert_eq!(body["termination_reason"], "expired");
        assert_eq!(body["status"], 403);
    }

    fn futures_body(resp: Resp) -> serde_json::Value {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            use http_body_util::BodyExt;
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice(&bytes).unwrap()
        })
    }
}
