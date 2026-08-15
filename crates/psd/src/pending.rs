//! Deferred responses (§Deferred Responses, §Interaction Required,
//! §Interaction Code Format): the `202` the agent gets while a human decides,
//! the interaction code that correlates the human's browser with the pending
//! request, and the in-process wake-up that makes `Prefer: wait=N` long-polls
//! return the moment a decision lands.
//!
//! The code is a **correlation identifier, not a credential**: presenting it
//! only locates the request; the decision itself is recorded by the
//! authenticated session. The agent relays the code to the person, so the
//! agent knows it — nothing the agent knows may authorize the decision.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use crate::problem::{Body, Resp};

/// Longest long-poll we hold a connection open for. 50 s, not 60: 60 is the
/// default idle timeout of many load balancers and reverse proxies, and a
/// hold sitting exactly on that boundary produces intermittent 502s. Operators
/// should set the proxy read timeout to 75 s or more.
pub const MAX_WAIT_SECS: u64 = 50;
/// `Retry-After` for a pending response.
pub const RETRY_AFTER_SECS: u64 = 5;

/// A fresh interaction code: 8 Crockford base32 symbols (40 bits), shown as
/// `XXXX-XXXX`. Returns `(display, hash)`.
pub fn new_code() -> (String, String) {
    let raw = aauth_core::rand_crockford(8);
    let display = format!("{}-{}", &raw[..4], &raw[4..]);
    (display, code_hash(&raw))
}

/// Normalize a code as typed or pasted by a human (§Interaction Code Format):
/// strip hyphens and whitespace, fold case, and fold the Crockford decode
/// aliases `I`/`L` → `1`, `O` → `0`.
pub fn normalize_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            u => u,
        })
        .collect()
}

/// The stored form of a code (normalized then hashed).
pub fn code_hash(code: &str) -> String {
    let normalized = normalize_code(code);
    let d = Sha256::digest(normalized.as_bytes());
    let mut out = String::with_capacity(64);
    for b in d {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Parse `Prefer: wait=N` (RFC 7240), capped at [`MAX_WAIT_SECS`].
pub fn prefer_wait(header: Option<String>) -> Option<Duration> {
    let h = header?;
    for part in h.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("wait=") {
            if let Ok(n) = v.trim().parse::<u64>() {
                return Some(Duration::from_secs(n.min(MAX_WAIT_SECS)));
            }
        }
    }
    None
}

/// The `202 Accepted` for a request waiting on the person.
pub fn accepted(
    issuer: &str,
    pending_id: &str,
    status: &str,
    interaction: Option<(&str, &str)>,
) -> Resp {
    let header = interaction.map(|(url, code)| {
        format!(
            "requirement=interaction; url={}; code={}",
            aauth_core::sfv::serialize_string(url),
            aauth_core::sfv::serialize_string(code)
        )
    });
    accepted_raw(
        issuer,
        pending_id,
        header.as_deref(),
        serde_json::json!({ "status": status }),
    )
}

/// A `202 Accepted` carrying an already-formed `AAuth-Requirement` value
/// (e.g. one an Access Server handed us to pass on) and a body.
pub fn accepted_raw(
    issuer: &str,
    pending_id: &str,
    requirement: Option<&str>,
    body: serde_json::Value,
) -> Resp {
    let mut b = Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("location", format!("{issuer}/pending/{pending_id}"))
        .header("retry-after", RETRY_AFTER_SECS.to_string())
        .header("cache-control", "no-store")
        .header("content-type", "application/json");
    if let Some(h) = requirement {
        b = b.header("aauth-requirement", h);
    }
    b.body(Body::new(Bytes::from(body.to_string()))).unwrap()
}

/// Wake-ups for long-polls, keyed by pending id. Entries are dropped when the
/// last waiter leaves or the request is decided.
#[derive(Default)]
pub struct PendingNotify {
    inner: Mutex<HashMap<String, Arc<Notify>>>,
}

impl PendingNotify {
    pub fn new() -> PendingNotify {
        PendingNotify::default()
    }

    fn handle(&self, id: &str) -> Arc<Notify> {
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        m.entry(id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Wait up to `dur` for a decision on `id`. Returns as soon as an
    /// in-process decision wakes it, or when `decided_elsewhere()` reports
    /// that another process (the operator CLI) decided — checked every
    /// 500 ms — or at the deadline.
    pub async fn wait(&self, id: &str, dur: Duration, decided_elsewhere: impl Fn() -> bool) {
        let n = self.handle(id);
        let deadline = tokio::time::Instant::now() + dur;
        let mut notified = std::pin::pin!(n.notified());
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return;
            }
            let slice = (deadline - now).min(Duration::from_millis(500));
            if tokio::time::timeout(slice, notified.as_mut()).await.is_ok() {
                return;
            }
            if decided_elsewhere() {
                return;
            }
        }
    }

    /// A decision landed on `id`: wake every waiter and forget the handle.
    pub fn decided(&self, id: &str) {
        let n = {
            let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            m.remove(id)
        };
        if let Some(n) = n {
            n.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_shape_and_normalization() {
        let (display, hash) = new_code();
        assert_eq!(display.len(), 9);
        assert_eq!(&display[4..5], "-");
        assert!(display
            .chars()
            .all(|c| c == '-' || "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c)));
        assert_eq!(hash.len(), 64);
        // hyphens, case and glyph aliases fold
        assert_eq!(code_hash(&display), hash);
        assert_eq!(code_hash(&display.to_lowercase()), hash);
        assert_eq!(code_hash(&display.replace('-', " ")), hash);
        assert_eq!(normalize_code("il-o0"), "1100");
        assert_ne!(code_hash("AAAA-AAAB"), code_hash("AAAA-AAAA"));
    }

    #[test]
    fn prefer_wait_parsing() {
        assert_eq!(prefer_wait(None), None);
        assert_eq!(
            prefer_wait(Some("wait=10".into())),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            prefer_wait(Some("respond-async, wait=600".into())),
            Some(Duration::from_secs(MAX_WAIT_SECS))
        );
        assert_eq!(prefer_wait(Some("wait=abc".into())), None);
    }

    #[tokio::test]
    async fn accepted_response_shape() {
        let resp = accepted(
            "https://ps.example",
            "pr-1",
            "pending",
            Some(("https://ps.example/consent", "A1B2-C3D4")),
        );
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "https://ps.example/pending/pr-1"
        );
        assert_eq!(resp.headers().get("retry-after").unwrap(), "5");
        assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(
            resp.headers().get("aauth-requirement").unwrap(),
            r#"requirement=interaction; url="https://ps.example/consent"; code="A1B2-C3D4""#
        );
        let resp = accepted("https://ps.example", "pr-1", "interacting", None);
        assert!(resp.headers().get("aauth-requirement").is_none());
    }

    #[tokio::test]
    async fn notify_wakes_waiters() {
        let n = Arc::new(PendingNotify::new());
        let n2 = n.clone();
        let waiter = tokio::spawn(async move {
            let start = std::time::Instant::now();
            n2.wait("x", Duration::from_secs(5), || false).await;
            start.elapsed()
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        n.decided("x");
        let elapsed = waiter.await.unwrap();
        assert!(elapsed < Duration::from_secs(2), "woke early: {elapsed:?}");
        // timeout path
        let start = std::time::Instant::now();
        n.wait("y", Duration::from_millis(30), || false).await;
        assert!(start.elapsed() >= Duration::from_millis(30));
        // cross-process fallback: a decision seen by polling ends the wait
        // within about one slice, not at the deadline
        let start = std::time::Instant::now();
        let flag = std::sync::atomic::AtomicBool::new(false);
        let checks = std::sync::atomic::AtomicUsize::new(0);
        n.wait("z", Duration::from_secs(10), || {
            checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            flag.swap(true, std::sync::atomic::Ordering::SeqCst)
        })
        .await;
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
        assert!(checks.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    }
}
