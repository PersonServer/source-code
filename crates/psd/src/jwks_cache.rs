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
//! Adapted from apd (MIT OR Apache-2.0).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use aauth_core::jwk::{Jwk, Jwks};
use aauth_core::sig::{SigError, SigErrorCode};
use tokio::sync::Mutex;

use crate::httpc::{self, EgressPolicy};

const FETCH_FLOOR: Duration = Duration::from_secs(60);
const MAX_AGE: Duration = Duration::from_secs(24 * 3600);
/// Detail-text marker for "refresh refused by the once-per-minute floor", so a
/// caller can tell it from "the kid is genuinely absent" without a new code.
pub const FLOOR_NOTE: &str = "fetch floor active";

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
    pub async fn get_key(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError> {
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
    pub async fn refresh_and_get(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError> {
        let cache_key = format!("{iss}|{dwk}");
        self.refresh_key(iss, dwk, kid, &cache_key).await
    }

    /// The issuer's metadata document (fetched and issuer-checked), from the
    /// cache when fresh. Used for display fields at the consent screen; the
    /// document is the same one JWKS discovery already validated.
    pub async fn get_metadata(&self, iss: &str, dwk: &str) -> Result<serde_json::Value, SigError> {
        let cache_key = format!("{iss}|{dwk}");
        {
            let entries = self.entries.lock().await;
            if let Some(entry) = entries.get(&cache_key) {
                if entry.fetched_at.elapsed() < MAX_AGE {
                    return Ok(entry.metadata.clone());
                }
            }
        }
        self.take_attempt(&cache_key).await?;
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

    async fn take_attempt(&self, cache_key: &str) -> Result<(), SigError> {
        let mut attempts = self.last_attempt.lock().await;
        if let Some(last) = attempts.get(cache_key) {
            if last.elapsed() < FETCH_FLOOR {
                return Err(SigError::new(
                    SigErrorCode::UnknownKey,
                    format!("discovery for {cache_key} rate-limited ({FLOOR_NOTE})"),
                ));
            }
        }
        // Recorded before the fetch so failures also consume the minute.
        attempts.insert(cache_key.to_string(), Instant::now());
        Ok(())
    }

    async fn refresh_key(
        &self,
        iss: &str,
        dwk: &str,
        kid: &str,
        cache_key: &str,
    ) -> Result<Jwk, SigError> {
        self.take_attempt(cache_key).await.map_err(|_| {
            SigError::new(
                SigErrorCode::UnknownKey,
                format!("kid '{kid}' not found for {iss} ({FLOOR_NOTE})"),
            )
        })?;
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
            SigError::new(
                SigErrorCode::UnknownKey,
                format!("kid '{kid}' not in JWKS of {iss}"),
            )
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
    ) -> Result<(serde_json::Value, Option<Jwks>), SigError> {
        let meta_url = format!("{iss}/.well-known/{dwk}");
        let metadata = httpc::get_json(&meta_url, &self.policy)
            .await
            .map_err(|e| SigError::new(SigErrorCode::UnknownKey, format!("metadata fetch: {e}")))?;
        // Host-poisoning defense (§Metadata Documents): the document must
        // claim the issuer it was fetched from, byte-for-byte.
        match metadata.get("issuer").and_then(|v| v.as_str()) {
            None => {
                return Err(SigError::new(
                    SigErrorCode::IssuerMissing,
                    format!("metadata at {meta_url} has no issuer"),
                ))
            }
            Some(i) if i != iss => {
                return Err(SigError::new(
                    SigErrorCode::IssuerMismatch,
                    format!("metadata issuer mismatch at {meta_url}"),
                ))
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
                ));
            }
        }
        let jwks_val = httpc::get_json(&jwks_uri, &self.policy)
            .await
            .map_err(|e| SigError::new(SigErrorCode::UnknownKey, format!("jwks fetch: {e}")))?;
        let jwks: Jwks = serde_json::from_value(jwks_val)
            .map_err(|e| SigError::new(SigErrorCode::InvalidKey, format!("invalid JWKS: {e}")))?;
        Ok((metadata, Some(jwks)))
    }
}
