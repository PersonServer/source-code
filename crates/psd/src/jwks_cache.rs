//! Issuer discovery and caching per the AAuth rules (§JWKS Discovery and
//! Caching, §Metadata Documents):
//!
//! - `{iss}/.well-known/{dwk}` → metadata (whose `issuer` MUST equal `iss`,
//!   else `issuer_missing` / `issuer_mismatch`) → `jwks_uri` → JWKS
//! - cache per issuer; never fetch the same issuer more than once per minute;
//!   discard after 24 h; refresh once on unknown `kid`
//! - egress admission on every fetch (via `httpc`)
//!
//! A Person Server verifies tokens from every Agent Provider (`aauth-agent.json`),
//! every resource (`aauth-resource.json`) and, four-party, Access Servers —
//! all foreign, so every `jwt`-scheme request goes through here. The metadata
//! document is cached alongside the JWKS because the consent screen also needs
//! it (an AP's `name`/`logo_uri`, a resource's `name`/`description`/
//! `access_mode`); one fetch serves both.
//!
//! Verification must never depend on a live fetch: a token is checked against
//! a cached key set, so an issuer being briefly unreachable cannot stop us
//! verifying tokens it already signed. The refresh floor exists for the
//! reverse reason — an unknown `kid` is the one legitimate trigger for a
//! refetch, and also the cheapest way for an attacker to make us hammer a
//! third party.
//!
//! "Could not ask the issuer" and "the issuer says no" are kept apart
//! ([`LookupError`]): a failed or floor-refused fetch says nothing about the
//! caller's key, and reporting it as `unknown_key` sends an agent developer
//! off to re-enrol when the fault is our egress or their provider's uptime.
//!
//! Adapted from apd (MIT OR Apache-2.0).

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use aauth_core::jwk::{Jwk, Jwks};
use aauth_core::sig::{SigError, SigErrorCode};
use tokio::sync::Mutex;

use crate::httpc::{self, EgressPolicy};
use crate::problem::ApiError;

const FETCH_FLOOR: Duration = Duration::from_secs(60);
const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

/// Why a key (or a metadata document) could not be produced.
#[derive(Debug)]
pub enum LookupError {
    /// The issuer was consulted and the answer is definitive — the `kid` is
    /// not in its key set, its metadata fails the issuer checks, its JWKS is
    /// malformed or cross-origin. A `Signature-Error` code.
    Sig(SigError),
    /// The issuer could not be consulted: the fetch failed (egress refused,
    /// DNS, timeout, non-2xx) or the once-per-minute floor forbids asking
    /// again yet after such a failure. Says nothing about the caller's key;
    /// the caller should retry after `retry_after_secs`.
    Unavailable {
        detail: String,
        retry_after_secs: u64,
    },
}

impl LookupError {
    /// Map to a response: `Unavailable` is always `503` with `Retry-After`,
    /// whatever endpoint was asked; `Sig` is mapped by the caller into its own
    /// vocabulary (`401 Signature-Error` for agent tokens, `400
    /// invalid_resource_token` for resource tokens, …).
    pub fn into_api(self, sig: impl FnOnce(SigError) -> ApiError) -> ApiError {
        match self {
            LookupError::Sig(e) => sig(e),
            LookupError::Unavailable {
                detail,
                retry_after_secs,
            } => ApiError::unavailable(detail, retry_after_secs),
        }
    }
}

impl From<SigError> for LookupError {
    fn from(e: SigError) -> Self {
        LookupError::Sig(e)
    }
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LookupError::Sig(e) => write!(f, "{e}"),
            LookupError::Unavailable { detail, .. } => write!(f, "{detail}"),
        }
    }
}

struct Entry {
    metadata: serde_json::Value,
    jwks: Option<Jwks>,
    fetched_at: Instant,
}

pub struct JwksCache {
    policy: EgressPolicy,
    /// Hosts explicitly admitted as cross-origin JWKS hosts (JWKS host differs
    /// from the metadata/issuer host). Empty = same-origin only.
    cross_origin_jwks_hosts: Vec<String>,
    entries: Mutex<HashMap<String, Entry>>,
    last_attempt: Mutex<HashMap<String, Instant>>,
}

impl JwksCache {
    pub fn new(policy: EgressPolicy, cross_origin_jwks_hosts: Vec<String>) -> JwksCache {
        JwksCache {
            policy,
            cross_origin_jwks_hosts,
            entries: Mutex::new(HashMap::new()),
            last_attempt: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve a key for `iss` (a server identifier) + `dwk` document + `kid`.
    pub async fn get_key(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, LookupError> {
        let cache_key = format!("{iss}|{dwk}");
        {
            let entries = self.entries.lock().await;
            if let Some(entry) = entries.get(&cache_key) {
                if entry.fetched_at.elapsed() < MAX_AGE {
                    if let Some(key) = entry.jwks.as_ref().and_then(|j| j.find(kid)) {
                        return Ok(key);
                    }
                }
            }
        }
        // Unknown kid (or no cache): refresh, subject to the per-issuer floor.
        self.refresh_key(iss, dwk, kid, &cache_key).await
    }

    /// Force a JWKS refresh and re-resolve `kid`, bypassing the cache-hit
    /// shortcut but still honoring the once-per-minute floor. Used when a
    /// cache-hit key fails signature verification (silent re-keying under the
    /// same `kid`): the Signature-Key draft says SHOULD refresh once and retry.
    pub async fn refresh_and_get(
        &self,
        iss: &str,
        dwk: &str,
        kid: &str,
    ) -> Result<Jwk, LookupError> {
        let cache_key = format!("{iss}|{dwk}");
        self.refresh_key(iss, dwk, kid, &cache_key).await
    }

    /// The issuer's metadata document (fetched and issuer-checked), from the
    /// cache when fresh. Used for display fields at the consent screen; the
    /// document is the same one JWKS discovery already validated.
    pub async fn get_metadata(
        &self,
        iss: &str,
        dwk: &str,
    ) -> Result<serde_json::Value, LookupError> {
        let cache_key = format!("{iss}|{dwk}");
        {
            let entries = self.entries.lock().await;
            if let Some(entry) = entries.get(&cache_key) {
                if entry.fetched_at.elapsed() < MAX_AGE {
                    return Ok(entry.metadata.clone());
                }
            }
        }
        if let Err(remaining) = self.take_attempt(&cache_key).await {
            return Err(LookupError::Unavailable {
                detail: format!(
                    "discovery for {iss} failed less than a minute ago and is not retried within \
                     the once-per-minute floor"
                ),
                retry_after_secs: remaining,
            });
        }
        let (metadata, jwks) = self.fetch(iss, dwk).await?;
        self.entries.lock().await.insert(
            cache_key,
            Entry {
                metadata: metadata.clone(),
                jwks,
                fetched_at: Instant::now(),
            },
        );
        Ok(metadata)
    }

    /// Claim the once-per-minute fetch slot for `cache_key`, or say how many
    /// seconds remain until it is free again. Recorded before the fetch so
    /// failures also consume the minute.
    async fn take_attempt(&self, cache_key: &str) -> Result<(), u64> {
        let mut attempts = self.last_attempt.lock().await;
        if let Some(last) = attempts.get(cache_key) {
            let elapsed = last.elapsed();
            if elapsed < FETCH_FLOOR {
                let remaining = FETCH_FLOOR - elapsed;
                return Err(remaining.as_secs().max(1));
            }
        }
        attempts.insert(cache_key.to_string(), Instant::now());
        Ok(())
    }

    async fn refresh_key(
        &self,
        iss: &str,
        dwk: &str,
        kid: &str,
        cache_key: &str,
    ) -> Result<Jwk, LookupError> {
        if let Err(remaining) = self.take_attempt(cache_key).await {
            // The floor is active. If the attempt it protects succeeded, that
            // key set is the freshest answer anyone can have for a minute: the
            // kid is in it (hand it back; the caller re-verifies) or it is
            // definitively unknown. If the attempt failed, we know nothing
            // about the key and must not pretend otherwise.
            let entries = self.entries.lock().await;
            return match entries.get(cache_key) {
                Some(entry) if entry.fetched_at.elapsed() < FETCH_FLOOR => {
                    match entry.jwks.as_ref().and_then(|j| j.find(kid)) {
                        Some(key) => Ok(key),
                        None => Err(LookupError::Sig(SigError::new(
                            SigErrorCode::UnknownKey,
                            format!(
                                "kid '{kid}' not in the JWKS of {iss} fetched less than a minute \
                                 ago"
                            ),
                        ))),
                    }
                }
                _ => Err(LookupError::Unavailable {
                    detail: format!(
                        "cannot verify the token: discovery for {iss} failed less than a minute \
                         ago and is not retried within the once-per-minute floor"
                    ),
                    retry_after_secs: remaining,
                }),
            };
        }
        let (metadata, jwks) = self.fetch(iss, dwk).await?;
        let found = jwks.as_ref().and_then(|j| j.find(kid));
        self.entries.lock().await.insert(
            cache_key.to_string(),
            Entry {
                metadata,
                jwks,
                fetched_at: Instant::now(),
            },
        );
        found.ok_or_else(|| {
            LookupError::Sig(SigError::new(
                SigErrorCode::UnknownKey,
                format!("kid '{kid}' not in JWKS of {iss}"),
            ))
        })
    }

    /// Fetch `{iss}/.well-known/{dwk}` and, when it names one, its JWKS. The
    /// JWKS is optional because a resource that issues no tokens MAY omit
    /// `jwks_uri` (§Resource Metadata) — its metadata is still useful for
    /// display.
    async fn fetch(
        &self,
        iss: &str,
        dwk: &str,
    ) -> Result<(serde_json::Value, Option<Jwks>), LookupError> {
        let unavailable = |what: &str, url: &str, e: &dyn fmt::Display| LookupError::Unavailable {
            detail: format!(
                "cannot verify the token: {what} for {iss} could not be fetched ({url}: {e}); \
                 this is not a statement about your key"
            ),
            retry_after_secs: FETCH_FLOOR.as_secs(),
        };
        let meta_url = format!("{iss}/.well-known/{dwk}");
        let metadata = httpc::get_json(&meta_url, &self.policy)
            .await
            .map_err(|e| unavailable("the metadata document", &meta_url, &e))?;
        // Host-poisoning defense (§Metadata Documents): the document must
        // claim the issuer it was fetched from, byte-for-byte.
        match metadata.get("issuer").and_then(|v| v.as_str()) {
            None => {
                return Err(SigError::new(
                    SigErrorCode::IssuerMissing,
                    format!("metadata at {meta_url} has no issuer"),
                )
                .into())
            }
            Some(i) if i != iss => {
                return Err(SigError::new(
                    SigErrorCode::IssuerMismatch,
                    format!("metadata issuer mismatch at {meta_url}"),
                )
                .into())
            }
            Some(_) => {}
        }
        let jwks_uri = match metadata.get("jwks_uri").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => return Ok((metadata, None)),
        };
        // Cross-origin admission (sig-key draft): a self-asserted metadata
        // document could point `jwks_uri` at any public host. Require the JWKS
        // host to equal the issuer host unless it is explicitly allow-listed.
        let iss_host = aauth_core::ident::host_of(iss);
        let jwks_host = aauth_core::ident::host_of(&jwks_uri);
        match (&iss_host, &jwks_host) {
            (Some(ih), Some(jh)) if ih == jh => {}
            (_, Some(jh)) if self.cross_origin_jwks_hosts.iter().any(|h| h == jh) => {}
            _ => {
                return Err(SigError::new(
                    SigErrorCode::InvalidKey,
                    format!(
                        "jwks_uri host for {iss} is cross-origin and not admitted \
                         (add it to jwks_cross_origin_hosts to allow)"
                    ),
                )
                .into());
            }
        }
        let jwks_val = httpc::get_json(&jwks_uri, &self.policy)
            .await
            .map_err(|e| unavailable("the JWKS", &jwks_uri, &e))?;
        let jwks: Jwks = serde_json::from_value(jwks_val)
            .map_err(|e| SigError::new(SigErrorCode::InvalidKey, format!("invalid JWKS: {e}")))?;
        Ok((metadata, Some(jwks)))
    }
}
