//! Passkey (WebAuthn) relying-party ceremonies for authenticating the person.
//!
//! `psd` stores no passwords: the person proves who they are with
//! a passkey, first registered through a one-time enrolment link and then
//! used to open a dashboard session and to record consent decisions.
//!
//! This module wraps [`webauthn_rp`] — a pure-Rust RP library (p256,
//! ed25519-dalek, rsa; no OpenSSL, so the single-binary story holds) — behind
//! a small storage-agnostic API:
//!
//! - registration: [`Passkeys::start_registration`] → browser
//!   `navigator.credentials.create()` → [`Passkeys::finish_registration`] →
//!   a [`NewCredential`] to persist
//! - authentication: [`Passkeys::start_authentication`] → browser
//!   `navigator.credentials.get()` (discoverable, so no username prompt) →
//!   [`Passkeys::finish_authentication`] with a lookup closure → the matched
//!   credential and any updated dynamic state (sign counter) to persist
//!
//! Pending ceremonies live in memory for a few minutes; a restart simply
//! invalidates them. Attestation is not verified: this is a self-hosted
//! deployment where the person enrols their own authenticator, and only
//! `attestation: "none"` semantics are needed.
//!
//! The RP ID is the issuer's host. WebAuthn forbids IP-address RP IDs, so a
//! development deployment that wants the UI must use a hostname issuer such
//! as `http://localhost:8430`.

use std::sync::Mutex;

use webauthn_rp::bin::{Decode, Encode};
use webauthn_rp::request::auth::{
    AuthenticationVerificationOptions, DiscoverableAuthenticationServerState,
    DiscoverableCredentialRequestOptions,
};
use webauthn_rp::request::register::{
    Nickname, PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity,
    RegistrationServerState, RegistrationVerificationOptions, UserHandle64, Username,
    USER_HANDLE_MAX_LEN,
};
use webauthn_rp::request::{
    AsciiDomain, FixedCapHashSet, InsertResult, PublicKeyCredentialDescriptor, RpId,
};
use webauthn_rp::response::register::{CompressedPubKey, DynamicState, StaticState};
use webauthn_rp::response::{AuthTransports, CredentialId};
use webauthn_rp::{AuthenticatedCredential, DiscoverableAuthentication64, Registration};

/// Bound on concurrently pending ceremonies (each is a few hundred bytes).
const MAX_PENDING: usize = 256;

/// The persisted public-key form `webauthn_rp` decodes into.
type StoredStaticState = StaticState<CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>>;

/// A credential produced by a successful registration, ready to persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCredential {
    pub cred_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    /// Opaque encoding of the public key + registration-time extension state.
    pub static_state: Vec<u8>,
    /// Opaque encoding of the sign counter, UV and backup flags.
    pub dynamic_state: Vec<u8>,
    /// Transport hints bit set.
    pub transports: u8,
}

/// A persisted credential, as [`Passkeys::finish_authentication`] needs it.
#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub cred_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub static_state: Vec<u8>,
    pub dynamic_state: Vec<u8>,
}

/// Outcome of a successful authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOutcome {
    pub cred_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    /// New dynamic state to persist (sign counter advanced, flags), if any.
    pub updated_dynamic_state: Option<Vec<u8>>,
}

pub struct Passkeys {
    rp_id: RpId,
    origin: String,
    reg: Mutex<FixedCapHashSet<RegistrationServerState<USER_HANDLE_MAX_LEN>>>,
    auth: Mutex<FixedCapHashSet<DiscoverableAuthenticationServerState>>,
}

impl std::fmt::Debug for Passkeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkeys")
            .field("origin", &self.origin)
            .finish()
    }
}

/// A fresh random 64-byte user handle (WebAuthn `user.id`), for a new person.
pub fn new_user_handle() -> Vec<u8> {
    UserHandle64::new().as_ref().to_vec()
}

fn user_handle(bytes: &[u8]) -> Result<UserHandle64, String> {
    let arr: [u8; USER_HANDLE_MAX_LEN] = bytes
        .try_into()
        .map_err(|_| "user handle must be 64 bytes".to_string())?;
    Ok(UserHandle64::from(arr))
}

impl Passkeys {
    /// Build for an issuer. The RP ID is the issuer host; the origin is the
    /// issuer itself (scheme + host [+ port]).
    pub fn new(issuer: &str) -> Result<Passkeys, String> {
        let host = aauth_core::ident::host_of(issuer)
            .ok_or_else(|| format!("issuer '{issuer}' has no host"))?;
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Err(format!(
                "issuer host '{host}' is an IP address; WebAuthn requires a domain RP ID — use a \
                 hostname issuer (e.g. http://localhost:8430 in development)"
            ));
        }
        let domain = AsciiDomain::try_from(host.clone())
            .map_err(|e| format!("issuer host '{host}' is not a valid RP ID: {e:?}"))?;
        Ok(Passkeys {
            rp_id: RpId::Domain(domain),
            origin: issuer.to_string(),
            reg: Mutex::new(FixedCapHashSet::new(MAX_PENDING)),
            auth: Mutex::new(FixedCapHashSet::new(MAX_PENDING)),
        })
    }

    /// Start a registration ceremony. Returns the
    /// `PublicKeyCredentialCreationOptionsJSON` the browser feeds to
    /// `PublicKeyCredential.parseCreationOptionsFromJSON()`. `existing` lists
    /// the person's already-registered credential ids so the authenticator
    /// does not overwrite one.
    pub fn start_registration(
        &self,
        user_handle_bytes: &[u8],
        name: &str,
        display_name: &str,
        existing: &[Vec<u8>],
    ) -> Result<serde_json::Value, String> {
        let uh = user_handle(user_handle_bytes)?;
        let username = Username::try_from(name).map_err(|e| format!("invalid user name: {e:?}"))?;
        let nick =
            Nickname::try_from(display_name).map_err(|e| format!("invalid display name: {e:?}"))?;
        let entity = PublicKeyCredentialUserEntity {
            name: username,
            id: &uh,
            display_name: Some(nick),
        };
        let mut exclude: Vec<PublicKeyCredentialDescriptor<Vec<u8>>> = Vec::new();
        for id in existing {
            let id = CredentialId::try_from(id.clone())
                .map_err(|e| format!("stored credential id is invalid: {e}"))?;
            exclude.push(PublicKeyCredentialDescriptor {
                id,
                transports: AuthTransports::NONE,
            });
        }
        let (server, client) =
            PublicKeyCredentialCreationOptions::passkey(&self.rp_id, entity, exclude)
                .start_ceremony()
                .map_err(|e| format!("cannot start registration: {e:?}"))?;
        let json = serde_json::to_value(&client).map_err(|e| e.to_string())?;
        let mut reg = self.reg.lock().unwrap_or_else(|e| e.into_inner());
        match reg.insert_or_replace_all_expired(server) {
            InsertResult::Success => Ok(json),
            other => Err(format!("too many pending registrations ({other:?})")),
        }
    }

    /// Finish a registration with the browser's `PublicKeyCredential.toJSON()`.
    pub fn finish_registration(&self, response_json: &[u8]) -> Result<NewCredential, String> {
        let registration = Registration::from_json_relaxed(response_json)
            .map_err(|e| format!("invalid registration response: {e}"))?;
        let challenge = registration
            .challenge_relaxed()
            .map_err(|e| format!("invalid clientDataJSON: {e}"))?;
        let server = {
            let mut reg = self.reg.lock().unwrap_or_else(|e| e.into_inner());
            reg.take(&challenge).ok_or_else(|| {
                "no pending registration for this challenge (expired?)".to_string()
            })?
        };
        let allowed = [self.origin.as_str()];
        let opts = RegistrationVerificationOptions::<&str, &str> {
            allowed_origins: &allowed,
            ..Default::default()
        };
        let cred = server
            .verify(&self.rp_id, &registration, &opts)
            .map_err(|e| format!("registration failed verification: {e}"))?;
        let static_state = cred
            .static_state()
            .encode()
            .map_err(|e| format!("encode static state: {e:?}"))?;
        let dynamic_state = cred
            .dynamic_state()
            .encode()
            .map_err(|e| format!("encode dynamic state: {e:?}"))?;
        let transports = cred
            .transports()
            .encode()
            .map_err(|e| format!("encode transports: {e:?}"))?;
        Ok(NewCredential {
            cred_id: cred.id().as_ref().to_vec(),
            user_handle: cred.user_id().as_ref().to_vec(),
            static_state,
            dynamic_state: dynamic_state.to_vec(),
            transports,
        })
    }

    /// Start a (discoverable) authentication ceremony. Returns the
    /// `PublicKeyCredentialRequestOptionsJSON` for
    /// `PublicKeyCredential.parseRequestOptionsFromJSON()`.
    pub fn start_authentication(&self) -> Result<serde_json::Value, String> {
        let (server, client) = DiscoverableCredentialRequestOptions::passkey(&self.rp_id)
            .start_ceremony()
            .map_err(|e| format!("cannot start authentication: {e:?}"))?;
        let json = serde_json::to_value(&client).map_err(|e| e.to_string())?;
        let mut auth = self.auth.lock().unwrap_or_else(|e| e.into_inner());
        match auth.insert_or_replace_all_expired(server) {
            InsertResult::Success => Ok(json),
            other => Err(format!("too many pending authentications ({other:?})")),
        }
    }

    /// Finish an authentication with the browser's `PublicKeyCredential.toJSON()`.
    /// `lookup` resolves the asserted credential id (must also match the
    /// asserted user handle — the caller checks that).
    pub fn finish_authentication(
        &self,
        response_json: &[u8],
        lookup: &dyn Fn(&[u8]) -> Option<StoredCredential>,
    ) -> Result<AuthOutcome, String> {
        let authentication = DiscoverableAuthentication64::from_json_relaxed(response_json)
            .map_err(|e| format!("invalid authentication response: {e}"))?;
        let challenge = authentication
            .challenge_relaxed()
            .map_err(|e| format!("invalid clientDataJSON: {e}"))?;
        let server = {
            let mut auth = self.auth.lock().unwrap_or_else(|e| e.into_inner());
            auth.take(&challenge).ok_or_else(|| {
                "no pending authentication for this challenge (expired?)".to_string()
            })?
        };
        let raw_id = authentication.raw_id();
        let stored = lookup(raw_id.as_ref()).ok_or_else(|| "unknown credential".to_string())?;
        if stored.user_handle.as_slice() != authentication.response().user_handle().as_ref() {
            return Err("credential does not belong to the asserted user".into());
        }
        let uh = user_handle(&stored.user_handle)?;
        let static_state: StoredStaticState =
            StaticState::decode(stored.static_state.as_slice())
                .map_err(|e| format!("stored static state is corrupt: {e:?}"))?;
        let dyn_bytes: [u8; 7] = stored
            .dynamic_state
            .as_slice()
            .try_into()
            .map_err(|_| "stored dynamic state has the wrong length".to_string())?;
        let dynamic_state = DynamicState::decode(dyn_bytes)
            .map_err(|e| format!("stored dynamic state is corrupt: {e:?}"))?;
        let cred_id = CredentialId::try_from(stored.cred_id.as_slice())
            .map_err(|e| format!("stored credential id is invalid: {e}"))?;
        let mut cred = AuthenticatedCredential::new(cred_id, &uh, static_state, dynamic_state)
            .map_err(|e| format!("stored credential is inconsistent: {e}"))?;
        let allowed = [self.origin.as_str()];
        let opts = AuthenticationVerificationOptions::<&str, &str> {
            allowed_origins: &allowed,
            ..Default::default()
        };
        let changed = server
            .verify(&self.rp_id, &authentication, &mut cred, &opts)
            .map_err(|e| format!("authentication failed verification: {e}"))?;
        let updated = if changed {
            Some(
                cred.dynamic_state()
                    .encode()
                    .map_err(|e| format!("encode dynamic state: {e:?}"))?
                    .to_vec(),
            )
        } else {
            None
        };
        Ok(AuthOutcome {
            cred_id: stored.cred_id,
            user_handle: stored.user_handle,
            updated_dynamic_state: updated,
        })
    }
}

/// A software authenticator for tests: an ES256 key that answers creation and
/// assertion requests the way a browser + authenticator would, so the full
/// ceremony runs without hardware.
#[cfg(test)]
pub mod fake_authenticator {
    use p256::ecdsa::{signature::Signer, SigningKey};
    use sha2::{Digest, Sha256};

    pub struct FakeAuthenticator {
        key: SigningKey,
        pub cred_id: Vec<u8>,
        pub sign_count: u32,
    }

    // Minimal canonical CBOR encoder for the shapes WebAuthn uses.
    fn cbor_uint(major: u8, n: u64, out: &mut Vec<u8>) {
        let mt = major << 5;
        if n < 24 {
            out.push(mt | n as u8);
        } else if n <= 0xff {
            out.push(mt | 24);
            out.push(n as u8);
        } else if n <= 0xffff {
            out.push(mt | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else if n <= 0xffff_ffff {
            out.push(mt | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        } else {
            out.push(mt | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
    pub fn cbor_int(i: i64, out: &mut Vec<u8>) {
        if i >= 0 {
            cbor_uint(0, i as u64, out)
        } else {
            cbor_uint(1, (-1 - i) as u64, out)
        }
    }
    pub fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
        cbor_uint(2, b.len() as u64, out);
        out.extend_from_slice(b);
    }
    pub fn cbor_text(s: &str, out: &mut Vec<u8>) {
        cbor_uint(3, s.len() as u64, out);
        out.extend_from_slice(s.as_bytes());
    }
    pub fn cbor_map_header(n: usize, out: &mut Vec<u8>) {
        cbor_uint(5, n as u64, out)
    }

    impl FakeAuthenticator {
        pub fn new() -> FakeAuthenticator {
            let mut seed = [0u8; 32];
            aauth_core::rand_bytes(&mut seed);
            let mut cred_id = vec![0u8; 16];
            aauth_core::rand_bytes(&mut cred_id);
            FakeAuthenticator {
                key: SigningKey::from_slice(&seed).unwrap(),
                cred_id,
                sign_count: 0,
            }
        }

        fn cose_key(&self) -> Vec<u8> {
            let point = self.key.verifying_key().to_encoded_point(false);
            let mut out = Vec::new();
            cbor_map_header(5, &mut out);
            cbor_int(1, &mut out);
            cbor_int(2, &mut out); // kty EC2
            cbor_int(3, &mut out);
            cbor_int(-7, &mut out); // alg ES256
            cbor_int(-1, &mut out);
            cbor_int(1, &mut out); // crv P-256
            cbor_int(-2, &mut out);
            cbor_bytes(point.x().unwrap(), &mut out);
            cbor_int(-3, &mut out);
            cbor_bytes(point.y().unwrap(), &mut out);
            out
        }

        fn client_data(&self, typ: &str, challenge_b64url: &str, origin: &str) -> Vec<u8> {
            serde_json::json!({
                "type": typ, "challenge": challenge_b64url, "origin": origin, "crossOrigin": false
            })
            .to_string()
            .into_bytes()
        }

        /// Answer `navigator.credentials.create()` for `options` (the JSON
        /// [`super::Passkeys::start_registration`] returned) at `origin`.
        pub fn create(&mut self, options: &serde_json::Value, origin: &str) -> serde_json::Value {
            let challenge = options["challenge"].as_str().unwrap();
            let rp_id = options["rp"]["id"].as_str().unwrap();
            let cdj = self.client_data("webauthn.create", challenge, origin);
            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
            auth_data.push(0x01 | 0x04 | 0x40); // UP | UV | AT
            auth_data.extend_from_slice(&self.sign_count.to_be_bytes());
            auth_data.extend_from_slice(&[0u8; 16]); // aaguid
            auth_data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
            auth_data.extend_from_slice(&self.cred_id);
            auth_data.extend_from_slice(&self.cose_key());
            let mut att = Vec::new();
            cbor_map_header(3, &mut att);
            cbor_text("fmt", &mut att);
            cbor_text("none", &mut att);
            cbor_text("attStmt", &mut att);
            cbor_map_header(0, &mut att);
            cbor_text("authData", &mut att);
            cbor_bytes(&auth_data, &mut att);
            let id = aauth_core::b64::encode(&self.cred_id);
            serde_json::json!({
                "id": id, "rawId": id, "type": "public-key",
                "authenticatorAttachment": "platform",
                "clientExtensionResults": {},
                "response": {
                    "clientDataJSON": aauth_core::b64::encode(&cdj),
                    "attestationObject": aauth_core::b64::encode(&att),
                    "transports": ["internal"],
                }
            })
        }

        /// Answer `navigator.credentials.get()` for `options` at `origin`,
        /// asserting `user_handle`.
        pub fn get(
            &mut self,
            options: &serde_json::Value,
            origin: &str,
            user_handle: &[u8],
        ) -> serde_json::Value {
            let challenge = options["challenge"].as_str().unwrap();
            let rp_id = options["rpId"].as_str().unwrap();
            let cdj = self.client_data("webauthn.get", challenge, origin);
            self.sign_count += 1;
            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
            auth_data.push(0x01 | 0x04); // UP | UV
            auth_data.extend_from_slice(&self.sign_count.to_be_bytes());
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(&cdj));
            let sig: p256::ecdsa::DerSignature = self.key.sign(&signed);
            let id = aauth_core::b64::encode(&self.cred_id);
            serde_json::json!({
                "id": id, "rawId": id, "type": "public-key",
                "authenticatorAttachment": "platform",
                "clientExtensionResults": {},
                "response": {
                    "clientDataJSON": aauth_core::b64::encode(&cdj),
                    "authenticatorData": aauth_core::b64::encode(&auth_data),
                    "signature": aauth_core::b64::encode(sig.as_bytes()),
                    "userHandle": aauth_core::b64::encode(user_handle),
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake_authenticator::FakeAuthenticator;
    use super::*;

    const ORIGIN: &str = "https://ps.example";

    fn register(pk: &Passkeys, auth: &mut FakeAuthenticator, uh: &[u8]) -> NewCredential {
        let options = pk.start_registration(uh, "alice", "Alice", &[]).unwrap();
        assert_eq!(options["rp"]["id"], "ps.example");
        assert_eq!(options["user"]["name"], "alice");
        assert!(options["pubKeyCredParams"].as_array().unwrap().len() >= 2);
        let response = auth.create(&options, ORIGIN);
        pk.finish_registration(response.to_string().as_bytes())
            .unwrap()
    }

    #[test]
    fn rp_id_rules() {
        assert!(Passkeys::new("http://127.0.0.1:8430").is_err());
        assert!(Passkeys::new("http://localhost:8430").is_ok());
        assert!(Passkeys::new("https://ps.example").is_ok());
    }

    #[test]
    fn register_persist_reload_authenticate() {
        let pk = Passkeys::new(ORIGIN).unwrap();
        let uh = new_user_handle();
        let mut auth = FakeAuthenticator::new();
        let cred = register(&pk, &mut auth, &uh);
        assert_eq!(cred.cred_id, auth.cred_id);
        assert_eq!(cred.user_handle, uh);
        assert_eq!(cred.dynamic_state.len(), 7);

        // "Persist" and authenticate against the stored form.
        let stored = StoredCredential {
            cred_id: cred.cred_id.clone(),
            user_handle: cred.user_handle.clone(),
            static_state: cred.static_state.clone(),
            dynamic_state: cred.dynamic_state.clone(),
        };
        let options = pk.start_authentication().unwrap();
        assert_eq!(options["rpId"], "ps.example");
        let response = auth.get(&options, ORIGIN, &uh);
        let lookup = |id: &[u8]| {
            if id == stored.cred_id.as_slice() {
                Some(stored.clone())
            } else {
                None
            }
        };
        let outcome = pk
            .finish_authentication(response.to_string().as_bytes(), &lookup)
            .unwrap();
        assert_eq!(outcome.cred_id, cred.cred_id);
        assert_eq!(outcome.user_handle, uh);
        // The sign counter moved 0 → 1, so the dynamic state was updated.
        assert!(outcome.updated_dynamic_state.is_some());

        // A second registration for the same person excludes the first id.
        let options = pk
            .start_registration(&uh, "alice", "Alice", std::slice::from_ref(&cred.cred_id))
            .unwrap();
        assert_eq!(
            options["excludeCredentials"][0]["id"],
            aauth_core::b64::encode(&cred.cred_id)
        );
    }

    #[test]
    fn wrong_origin_challenge_and_user_are_rejected() {
        let pk = Passkeys::new(ORIGIN).unwrap();
        let uh = new_user_handle();
        let mut auth = FakeAuthenticator::new();

        // Origin mismatch at registration.
        let options = pk.start_registration(&uh, "alice", "Alice", &[]).unwrap();
        let response = auth.create(&options, "https://evil.example");
        assert!(pk
            .finish_registration(response.to_string().as_bytes())
            .is_err());
        // The challenge was consumed by the failed attempt: replaying fails too.
        let response = auth.create(&options, ORIGIN);
        assert!(pk
            .finish_registration(response.to_string().as_bytes())
            .is_err());

        let cred = register(&pk, &mut auth, &uh);
        let stored = StoredCredential {
            cred_id: cred.cred_id.clone(),
            user_handle: cred.user_handle.clone(),
            static_state: cred.static_state.clone(),
            dynamic_state: cred.dynamic_state.clone(),
        };
        let lookup = |id: &[u8]| {
            if id == stored.cred_id.as_slice() {
                Some(stored.clone())
            } else {
                None
            }
        };

        // Origin mismatch at authentication.
        let options = pk.start_authentication().unwrap();
        let response = auth.get(&options, "https://evil.example", &uh);
        assert!(pk
            .finish_authentication(response.to_string().as_bytes(), &lookup)
            .is_err());

        // Unknown challenge (never started).
        let mut forged = options.clone();
        forged["challenge"] = serde_json::Value::String(aauth_core::b64::encode(&[7u8; 16]));
        let response = auth.get(&forged, ORIGIN, &uh);
        assert!(pk
            .finish_authentication(response.to_string().as_bytes(), &lookup)
            .is_err());

        // Asserting someone else's user handle for this credential.
        let options = pk.start_authentication().unwrap();
        let other = new_user_handle();
        let response = auth.get(&options, ORIGIN, &other);
        let err = pk
            .finish_authentication(response.to_string().as_bytes(), &lookup)
            .unwrap_err();
        assert!(err.contains("does not belong"), "{err}");

        // A signature by a different key over a valid-looking assertion.
        let options = pk.start_authentication().unwrap();
        let mut impostor = FakeAuthenticator::new();
        impostor.cred_id = auth.cred_id.clone();
        let response = impostor.get(&options, ORIGIN, &uh);
        assert!(pk
            .finish_authentication(response.to_string().as_bytes(), &lookup)
            .is_err());
    }
}
