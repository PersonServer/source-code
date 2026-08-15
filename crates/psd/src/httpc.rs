//! Minimal outbound HTTPS client with the egress admission rules the
//! Signature-Key draft requires of JWKS/metadata fetchers:
//!
//! - HTTPS only (plain HTTP allowed only in insecure_dev_mode)
//! - redirects are never followed
//! - private / loopback / link-local destinations rejected (unless dev mode)
//! - the resolved IP is pinned for the connection (DNS-rebinding defense)
//! - response size cap and timeout
//!
//! A Person Server fetches Agent Provider metadata, resource metadata and
//! (four-party) Access Server endpoints from URLs an attacker chose — every
//! outbound request in `psd` goes through this module.
//!
//! Copied from apd (MIT OR Apache-2.0), with the admission block factored
//! into [`admit`].

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub struct EgressPolicy {
    pub allow_private: bool,
    pub allow_http: bool,
    pub max_response_bytes: usize,
    pub timeout: Duration,
}

impl EgressPolicy {
    /// `insecure_dev` flips *both* `allow_private` and `allow_http` — that is
    /// what lets tests and local development talk to a mock server on
    /// loopback, and exactly why the flag must never be on in production.
    pub fn from_config(insecure_dev: bool) -> EgressPolicy {
        EgressPolicy {
            allow_private: insecure_dev,
            allow_http: insecure_dev,
            max_response_bytes: 64 * 1024,
            timeout: Duration::from_secs(10),
        }
    }
}

/// RFC 2606 / RFC 6761 names that never resolve on the public Internet.
fn reserved_tld(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    ["example", "invalid", "test"]
        .iter()
        .any(|t| h == *t || h.ends_with(&format!(".{t}")))
}

fn ip_is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
                || (o[0] == 198 && (o[1] & 0xFE) == 18) // 198.18.0.0/15
                || o[0] >= 240) // 240.0.0.0/4
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xFE00) == 0xFC00 // fc00::/7 unique local
                || (seg[0] & 0xFFC0) == 0xFE80 // fe80::/10 link local
                || (seg[0] == 0x2001 && seg[1] == 0x0DB8)) // documentation
        }
    }
}

struct ParsedUrl {
    https: bool,
    host: String,
    port: u16,
    path_and_query: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("unsupported URL scheme".into());
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if hostport.contains('@') {
        return Err("userinfo in URL rejected".into());
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse::<u16>().map_err(|e| e.to_string())?)
        }
        _ => (hostport.to_string(), if https { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err("empty host".into());
    }
    Ok(ParsedUrl {
        https,
        host,
        port,
        path_and_query: path.to_string(),
    })
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// GET a URL and return the body bytes. Enforces the egress policy.
pub async fn get(url: &str, policy: &EgressPolicy) -> Result<Bytes, String> {
    tokio::time::timeout(policy.timeout, get_inner(url, policy))
        .await
        .map_err(|_| format!("timeout fetching {url}"))?
}

/// GET a URL and parse the body as JSON.
pub async fn get_json(url: &str, policy: &EgressPolicy) -> Result<serde_json::Value, String> {
    let body = get(url, policy).await?;
    serde_json::from_slice(&body).map_err(|e| format!("invalid JSON from {url}: {e}"))
}

/// POST a JSON body with caller-supplied headers (the AAuth signature headers),
/// under the same egress admission as [`get`]. Returns the response status so
/// the caller can distinguish "revoked" from "unknown token" without treating a
/// `404` as a transport failure.
pub async fn post_json(
    url: &str,
    body: &[u8],
    headers: &[(String, String)],
    policy: &EgressPolicy,
) -> Result<u16, String> {
    request("POST", url, headers, Some(body), policy)
        .await
        .map(|r| r.status)
}

/// A response from [`request`]: status, lowercase header names, body (capped).
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// A signed request to another AAuth server (an Access Server's token
/// endpoint or pending URL) under the same egress admission as [`get`]:
/// redirects are never followed; every status is returned to the caller,
/// which decides what it means. Body capped at `max_response_bytes`.
pub async fn request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    policy: &EgressPolicy,
) -> Result<HttpResponse, String> {
    tokio::time::timeout(
        policy.timeout,
        request_inner(method, url, headers, body, policy),
    )
    .await
    .map_err(|_| format!("timeout on {method} {url}"))?
}

async fn request_inner(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    policy: &EgressPolicy,
) -> Result<HttpResponse, String> {
    let parsed = parse_url(url)?;
    let addrs = admit(&parsed, policy).await?;
    let stream = connect_any(&addrs).await?;
    let response = if parsed.https {
        let server_name = rustls::pki_types::ServerName::try_from(parsed.host.clone())
            .map_err(|_| "invalid TLS server name".to_string())?;
        let tls = TlsConnector::from(tls_config())
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("tls handshake with {}: {e}", parsed.host))?;
        send_request(TokioIo::new(tls), method, &parsed, headers, body).await?
    } else {
        send_request(TokioIo::new(stream), method, &parsed, headers, body).await?
    };
    let (parts, incoming) = response.into_parts();
    if parts.status.is_redirection() {
        return Err(format!("redirect from {url} refused"));
    }
    let hdrs: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter_map(|(n, v)| {
            v.to_str()
                .ok()
                .map(|v| (n.as_str().to_string(), v.to_string()))
        })
        .collect();
    let collected = http_body_util::Limited::new(incoming, policy.max_response_bytes)
        .collect()
        .await
        .map_err(|e| format!("body read from {url}: {e}"))?;
    Ok(HttpResponse {
        status: parts.status.as_u16(),
        headers: hdrs,
        body: collected.to_bytes(),
    })
}

async fn send_request<I>(
    io: I,
    method: &str,
    parsed: &ParsedUrl,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<hyper::Response<hyper::body::Incoming>, String>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("http handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut req = hyper::Request::builder()
        .method(method)
        .uri(&parsed.path_and_query)
        .header("host", authority_header(parsed))
        .header("accept", "application/json")
        .header("user-agent", concat!("psd/", env!("CARGO_PKG_VERSION")));
    if body.is_some() {
        req = req.header("content-type", "application/json");
    }
    for (name, value) in headers {
        req = req.header(name.as_str(), value.as_str());
    }
    let req = req
        .body(http_body_util::Full::new(Bytes::copy_from_slice(
            body.unwrap_or(&[]),
        )))
        .map_err(|e| e.to_string())?;
    sender.send_request(req).await.map_err(|e| e.to_string())
}

/// Split a URL into the `@authority` and `@path` values an RFC 9421 signature
/// must cover, so a caller can sign a request this module will then send.
pub fn signing_parts(url: &str) -> Result<(String, String), String> {
    let parsed = parse_url(url)?;
    let path = parsed
        .path_and_query
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();
    Ok((authority_header(&parsed), path))
}

/// The `Host` header value (and the `@authority` signature component): host,
/// plus the port only when it is not the scheme default.
fn authority_header(parsed: &ParsedUrl) -> String {
    if (parsed.https && parsed.port != 443) || (!parsed.https && parsed.port != 80) {
        format!("{}:{}", parsed.host, parsed.port)
    } else {
        parsed.host.clone()
    }
}

/// Resolve a host and admit its addresses under the egress policy. Under a
/// strict policy the whole answer is refused if *any* address is private
/// (mixed public/private resolution smells like rebinding), so everything
/// returned has been vetted; the caller connects to them in turn — a
/// dual-stack name whose service listens on one family must not fail on the
/// other. TLS name verification still uses the hostname.
async fn admit(parsed: &ParsedUrl, policy: &EgressPolicy) -> Result<Vec<SocketAddr>, String> {
    if !parsed.https && !policy.allow_http {
        return Err("plain http egress not allowed".into());
    }
    if reserved_tld(&parsed.host) {
        // RFC 2606 / RFC 6761: never resolves legitimately; refusing before
        // DNS avoids a resolver round-trip an attacker (or a test) can induce.
        return Err(format!("host {} is under a reserved TLD", parsed.host));
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((parsed.host.as_str(), parsed.port))
        .await
        .map_err(|e| format!("dns error for {}: {e}", parsed.host))?
        .collect();
    if !policy.allow_private && addrs.iter().any(|a| !ip_is_public(&a.ip())) {
        return Err(format!(
            "host {} resolves to private addresses",
            parsed.host
        ));
    }
    let admitted: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| policy.allow_private || ip_is_public(&a.ip()))
        .collect();
    if admitted.is_empty() {
        return Err(format!("no admissible address for {}", parsed.host));
    }
    Ok(admitted)
}

/// Connect to the first admitted address that answers.
async fn connect_any(addrs: &[SocketAddr]) -> Result<TcpStream, String> {
    let mut last = String::from("no address");
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(s) => {
                s.set_nodelay(true).ok();
                return Ok(s);
            }
            Err(e) => last = format!("connect {addr}: {e}"),
        }
    }
    Err(last)
}

async fn get_inner(url: &str, policy: &EgressPolicy) -> Result<Bytes, String> {
    let parsed = parse_url(url)?;
    let addrs = admit(&parsed, policy).await?;
    let stream = connect_any(&addrs).await?;

    let response = if parsed.https {
        let server_name = rustls::pki_types::ServerName::try_from(parsed.host.clone())
            .map_err(|_| "invalid TLS server name".to_string())?;
        let tls = TlsConnector::from(tls_config())
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("tls handshake with {}: {e}", parsed.host))?;
        send_get(TokioIo::new(tls), &parsed).await?
    } else {
        send_get(TokioIo::new(stream), &parsed).await?
    };

    let (parts, body) = response.into_parts();
    if parts.status.is_redirection() {
        return Err(format!("redirect from {url} refused"));
    }
    if !parts.status.is_success() {
        return Err(format!("HTTP {} from {url}", parts.status));
    }
    let collected = http_body_util::Limited::new(body, policy.max_response_bytes)
        .collect()
        .await
        .map_err(|e| format!("body read from {url}: {e}"))?;
    Ok(collected.to_bytes())
}

async fn send_get<I>(
    io: I,
    parsed: &ParsedUrl,
) -> Result<hyper::Response<hyper::body::Incoming>, String>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("http handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri(&parsed.path_and_query)
        .header("host", authority_header(parsed))
        .header("accept", "application/json")
        .header("user-agent", concat!("psd/", env!("CARGO_PKG_VERSION")))
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|e| e.to_string())?;
    sender.send_request(req).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        let u = parse_url("https://a.example/.well-known/x.json").unwrap();
        assert!(u.https);
        assert_eq!(u.host, "a.example");
        assert_eq!(u.port, 443);
        assert_eq!(u.path_and_query, "/.well-known/x.json");
        let u = parse_url("http://127.0.0.1:8081").unwrap();
        assert_eq!(u.port, 8081);
        assert_eq!(u.path_and_query, "/");
        assert!(parse_url("ftp://x").is_err());
        assert!(parse_url("https://user@x.example/").is_err());
    }

    #[test]
    fn signing_parts_strip_default_port_and_query() {
        assert_eq!(
            signing_parts("https://r.example/revoke?x=1").unwrap(),
            ("r.example".to_string(), "/revoke".to_string())
        );
        assert_eq!(
            signing_parts("http://127.0.0.1:9000/a/b").unwrap(),
            ("127.0.0.1:9000".to_string(), "/a/b".to_string())
        );
    }

    #[test]
    fn ip_admission() {
        let public: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(ip_is_public(&public));
        for bad in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
        ] {
            let ip: IpAddr = bad.parse().unwrap();
            assert!(!ip_is_public(&ip), "{bad} must be rejected");
        }
        let v6_public: IpAddr = "2606:2800:220:1::1".parse().unwrap();
        assert!(ip_is_public(&v6_public));
    }

    #[tokio::test]
    async fn reserved_tlds_never_hit_dns() {
        let policy = EgressPolicy::from_config(true);
        for u in [
            "https://resource.example/x",
            "http://a.b.test/",
            "https://foo.invalid",
        ] {
            let err = get(u, &policy).await.unwrap_err();
            assert!(err.contains("reserved TLD"), "{u}: {err}");
        }
        assert!(!reserved_tld("example.com"));
        assert!(!reserved_tld("localhost"));
        assert!(reserved_tld("example."));
    }

    #[tokio::test]
    async fn production_policy_refuses_loopback_and_http() {
        let policy = EgressPolicy::from_config(false);
        let err = get("http://127.0.0.1:1/x", &policy).await.unwrap_err();
        assert!(err.contains("plain http egress not allowed"), "{err}");
        let err = get("https://127.0.0.1:1/x", &policy).await.unwrap_err();
        assert!(err.contains("private addresses"), "{err}");
    }
}
