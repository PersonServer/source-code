//! PS signing keys and the pairwise secret: generation, rotation, JWKS.
//!
//! The keys file holds Ed25519 seeds plus the secret that derives directed
//! `sub` values. Rotation appends a new signing key and marks it active; old
//! public keys stay published until every token signed with them has expired
//! (person and auth tokens live <= 1 h), then can be pruned with
//! `psd keygen --prune-days`.
//!
//! The pairwise secret is never rotated by this tool: `sub` values are stored
//! once derived (see `store::directed_sub`), so a rotation would only affect
//! resources the person has not yet used — but it would also make a lost
//! database unrecoverable from the keys file. Treat it as a signing key: back
//! it up, never log it, and understand that its loss re-identifies every
//! person at every resource.
//!
//! Adapted from apd (MIT OR Apache-2.0).

use aauth_core::{b64, jwk::Jwk, now_unix};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub active: String,
    pub keys: Vec<KeyEntry>,
    /// base64url 32-byte secret for directed-identifier derivation — SECRET.
    /// Optional in the file so a keys file from an older build loads far
    /// enough to explain what to do; required at runtime.
    #[serde(default)]
    pub pairwise_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub kid: String,
    /// base64url Ed25519 seed (32 bytes) — SECRET.
    pub d: String,
    pub created_at: u64,
}

pub struct KeySet {
    pub active_kid: String,
    pub active_key: SigningKey,
    /// All public keys, for the JWKS and for verifying tokens we issued
    /// (matched by `kid`), active first.
    pub public_jwks: Vec<Jwk>,
    pairwise_secret: [u8; 32],
}

/// Never prints secret material.
impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySet")
            .field("active_kid", &self.active_kid)
            .field("public_keys", &self.public_jwks.len())
            .field("pairwise_secret", &"<redacted>")
            .finish()
    }
}

impl KeySet {
    pub fn load(path: &str) -> Result<KeySet, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read keys file {path}: {e} (run `psd keygen` first)"))?;
        let kf: KeyFile =
            serde_json::from_str(&raw).map_err(|e| format!("invalid keys file {path}: {e}"))?;
        KeySet::from_keyfile(&kf).map_err(|e| format!("keys file {path}: {e}"))
    }

    pub fn from_keyfile(kf: &KeyFile) -> Result<KeySet, String> {
        if kf.keys.is_empty() {
            return Err("contains no keys".into());
        }
        let secret_b64 = kf.pairwise_secret.as_deref().ok_or_else(|| {
            "has no pairwise_secret; run `psd keygen --keys <path>` to add one".to_string()
        })?;
        let pairwise_secret: [u8; 32] =
            b64::decode_fixed(secret_b64).map_err(|e| format!("bad pairwise_secret: {e}"))?;
        let mut public_jwks = Vec::new();
        let mut active_key = None;
        // active key's JWK first in the JWKS
        let mut ordered: Vec<&KeyEntry> = kf.keys.iter().collect();
        ordered.sort_by_key(|k| if k.kid == kf.active { 0 } else { 1 });
        for entry in ordered {
            let seed: [u8; 32] = b64::decode_fixed(&entry.d)
                .map_err(|e| format!("bad key seed for kid {}: {e}", entry.kid))?;
            let sk = SigningKey::from_bytes(&seed);
            let mut jwk = Jwk::from_verifying_key(&sk.verifying_key());
            jwk.kid = Some(entry.kid.clone());
            jwk.alg = Some(aauth_core::jwk::ALG_ED25519.into());
            jwk.use_ = Some("sig".into());
            public_jwks.push(jwk);
            if entry.kid == kf.active {
                active_key = Some(sk.clone());
            }
        }
        let active_key =
            active_key.ok_or_else(|| format!("active kid '{}' not present in keys", kf.active))?;
        Ok(KeySet {
            active_kid: kf.active.clone(),
            active_key,
            public_jwks,
            pairwise_secret,
        })
    }

    /// A fresh in-memory key set (tests, throwaway runs).
    #[cfg(test)]
    pub fn generate() -> KeySet {
        let kf = KeyFile {
            active: String::new(),
            keys: Vec::new(),
            pairwise_secret: None,
        };
        let kf = fresh_keyfile(kf);
        KeySet::from_keyfile(&kf).expect("fresh keyfile is valid")
    }

    pub fn find_public(&self, kid: &str) -> Option<&Jwk> {
        self.public_jwks
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid))
    }

    /// The JWKS document body. Every key carries a fully-specified `alg`.
    pub fn jwks_json(&self) -> serde_json::Value {
        serde_json::json!({ "keys": self.public_jwks })
    }

    /// Derive the directed (pairwise pseudonymous) `sub` for a person at an
    /// audience: `base64url(HMAC-SHA256(secret, len(person_id) || person_id
    /// || audience))`. The length prefix removes the concatenation ambiguity
    /// of `person_id || audience`. Deterministic, so a lost database with a
    /// surviving keys file reproduces the same values; the store's
    /// `UNIQUE(sub)` is what makes "unique within the issuer" a guarantee.
    pub fn derive_sub(&self, person_id: &str, audience: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.pairwise_secret)
            .expect("HMAC accepts any key length");
        mac.update(&(person_id.len() as u64).to_be_bytes());
        mac.update(person_id.as_bytes());
        mac.update(audience.as_bytes());
        b64::encode(&mac.finalize().into_bytes())
    }
}

fn new_entry() -> KeyEntry {
    let mut seed = [0u8; 32];
    aauth_core::rand_bytes(&mut seed);
    KeyEntry {
        kid: format!("ps-{}", aauth_core::rand_id(10)),
        d: b64::encode(&seed),
        created_at: now_unix(),
    }
}

fn new_pairwise_secret() -> String {
    let mut secret = [0u8; 32];
    aauth_core::rand_bytes(&mut secret);
    b64::encode(&secret)
}

fn fresh_keyfile(mut kf: KeyFile) -> KeyFile {
    let entry = new_entry();
    kf.active = entry.kid.clone();
    kf.keys = vec![entry];
    kf.pairwise_secret = Some(new_pairwise_secret());
    kf
}

/// `psd keygen`: create the keys file, or rotate/prune an existing one. A
/// pre-existing file without a pairwise secret gains one.
pub fn keygen(
    path: &str,
    rotate: bool,
    prune_older_than_secs: Option<u64>,
) -> Result<String, String> {
    let existing = std::fs::read_to_string(path).ok();
    let mut kf: KeyFile = match existing {
        Some(raw) => serde_json::from_str(&raw).map_err(|e| format!("invalid keys file: {e}"))?,
        None => {
            let kf = fresh_keyfile(KeyFile {
                active: String::new(),
                keys: Vec::new(),
                pairwise_secret: None,
            });
            write_keyfile(path, &kf)?;
            return Ok(format!(
                "created {path} with new active key '{}' and a pairwise secret",
                kf.active
            ));
        }
    };
    let mut msgs: Vec<String> = Vec::new();
    if kf.pairwise_secret.is_none() {
        kf.pairwise_secret = Some(new_pairwise_secret());
        msgs.push("added missing pairwise secret".into());
    }
    if rotate {
        let entry = new_entry();
        msgs.push(format!("rotated: new active key '{}'", entry.kid));
        kf.active = entry.kid.clone();
        kf.keys.push(entry);
    }
    if let Some(age) = prune_older_than_secs {
        let cutoff = now_unix().saturating_sub(age);
        let active = kf.active.clone();
        let before = kf.keys.len();
        kf.keys
            .retain(|k| k.kid == active || k.created_at >= cutoff);
        msgs.push(format!("pruned {} old keys", before - kf.keys.len()));
    }
    if msgs.is_empty() {
        return Ok(format!(
            "keys file {path} exists (active '{}', {} keys). Use --rotate to rotate.",
            kf.active,
            kf.keys.len()
        ));
    }
    write_keyfile(path, &kf)?;
    Ok(msgs.join("; "))
}

fn write_keyfile(path: &str, kf: &KeyFile) -> Result<(), String> {
    let tmp = format!("{path}.tmp");
    let data = serde_json::to_string_pretty(kf).unwrap();
    std::fs::write(&tmp, &data).map_err(|e| format!("cannot write {tmp}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot move {tmp} into place: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("psd-keys-test-{}", aauth_core::rand_id(8)));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name).to_string_lossy().into_owned()
    }

    #[test]
    fn keygen_create_rotate_prune() {
        let path = temp_path("keys.json");
        let msg = keygen(&path, false, None).unwrap();
        assert!(msg.starts_with("created"), "{msg}");
        let ks = KeySet::load(&path).unwrap();
        assert_eq!(ks.public_jwks.len(), 1);
        assert_eq!(ks.public_jwks[0].alg.as_deref(), Some("Ed25519"));
        assert!(ks.active_kid.starts_with("ps-"));

        // no-op
        let msg = keygen(&path, false, None).unwrap();
        assert!(msg.contains("exists"), "{msg}");

        // rotate: two keys, active first in the JWKS, old one still published
        let old_active = ks.active_kid.clone();
        keygen(&path, true, None).unwrap();
        let ks2 = KeySet::load(&path).unwrap();
        assert_eq!(ks2.public_jwks.len(), 2);
        assert_ne!(ks2.active_kid, old_active);
        assert_eq!(
            ks2.public_jwks[0].kid.as_deref(),
            Some(ks2.active_kid.as_str())
        );
        assert!(ks2.find_public(&old_active).is_some());

        // prune with a zero-age cutoff keeps only the active key
        keygen(&path, false, Some(0)).unwrap();
        // created_at >= cutoff (== now) keeps keys created this second; force
        // the old key into the past to exercise the retain.
        let mut kf: KeyFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for k in kf.keys.iter_mut() {
            if k.kid == old_active {
                k.created_at = 1;
            }
        }
        write_keyfile(&path, &kf).unwrap();
        keygen(&path, false, Some(3600)).unwrap();
        let ks3 = KeySet::load(&path).unwrap();
        assert_eq!(ks3.public_jwks.len(), 1);
        assert!(ks3.find_public(&old_active).is_none());
    }

    #[test]
    fn missing_pairwise_secret_is_added_by_keygen_and_required_by_load() {
        let path = temp_path("keys.json");
        keygen(&path, false, None).unwrap();
        let mut kf: KeyFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        kf.pairwise_secret = None;
        write_keyfile(&path, &kf).unwrap();
        let err = KeySet::load(&path).unwrap_err();
        assert!(err.contains("pairwise_secret"), "{err}");
        let msg = keygen(&path, false, None).unwrap();
        assert!(msg.contains("pairwise secret"), "{msg}");
        KeySet::load(&path).unwrap();
    }

    #[test]
    fn derive_sub_is_pairwise_and_unambiguous() {
        let ks = KeySet::generate();
        let a = ks.derive_sub("p1", "https://r1.example");
        let b = ks.derive_sub("p1", "https://r2.example");
        let c = ks.derive_sub("p2", "https://r1.example");
        assert_ne!(a, b, "different audiences must not correlate");
        assert_ne!(a, c, "different persons must differ");
        assert_eq!(
            a,
            ks.derive_sub("p1", "https://r1.example"),
            "deterministic"
        );
        // concatenation ambiguity: ("ab","c") vs ("a","bc")
        assert_ne!(ks.derive_sub("ab", "c"), ks.derive_sub("a", "bc"));
        // and different secrets give different values
        assert_ne!(a, KeySet::generate().derive_sub("p1", "https://r1.example"));
        assert!(!a.contains('='), "unpadded base64url");
    }
}
