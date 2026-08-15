//! Multi-algorithm public JWKs for third-party ID tokens (OIDC person login).
//!
//! psd's own tokens are Ed25519-only, but enterprise identity providers
//! (Okta, Entra, Google Workspace, Keycloak) sign ID tokens with RSA and
//! ECDSA. Verification uses `ring` (already in the tree via rustls):
//! supported JWS algs are EdDSA/Ed25519, RS256/RS384/RS512, ES256/ES384.
//!
//! Note on `EdDSA` vs `Ed25519`: the sig-key §3.3 rule forbidding the
//! polymorphic `EdDSA` identifier governs *AAuth-native* keys and tokens
//! (which this crate mints and verifies elsewhere). An IdP's ID token is not
//! an AAuth artifact, so we accept both the polymorphic `EdDSA` (still
//! emitted by most IdPs today) and the fully-specified `Ed25519` (RFC 9864),
//! mapping each to an Ed25519 key.
//!
//! Adapted from apd (MIT OR Apache-2.0).

use aauth_core::b64;

/// A parsed public JWK of any supported type.
#[derive(Debug, Clone)]
pub struct AnyJwk {
    pub kid: Option<String>,
    pub alg: Option<String>,
    pub key: KeyMaterial,
}

#[derive(Debug, Clone)]
pub enum KeyMaterial {
    /// OKP / Ed25519 (x = 32 bytes)
    Ed25519 { x: Vec<u8> },
    /// RSA (n, e big-endian)
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// EC P-256 (x, y = 32 bytes each)
    P256 { x: Vec<u8>, y: Vec<u8> },
    /// EC P-384 (x, y = 48 bytes each)
    P384 { x: Vec<u8>, y: Vec<u8> },
}

impl AnyJwk {
    /// Parse one JWK object. Returns None for unsupported key types rather
    /// than failing, so a mixed JWKS still loads.
    pub fn parse(value: &serde_json::Value) -> Option<AnyJwk> {
        let kid = value.get("kid").and_then(|v| v.as_str()).map(String::from);
        let alg = value.get("alg").and_then(|v| v.as_str()).map(String::from);
        let kty = value.get("kty")?.as_str()?;
        let get = |name: &str| -> Option<Vec<u8>> { b64::decode(value.get(name)?.as_str()?).ok() };
        let key = match kty {
            "OKP" => {
                if value.get("crv")?.as_str()? != "Ed25519" {
                    return None;
                }
                let x = get("x")?;
                if x.len() != 32 {
                    return None;
                }
                KeyMaterial::Ed25519 { x }
            }
            "RSA" => KeyMaterial::Rsa {
                n: get("n")?,
                e: get("e")?,
            },
            "EC" => {
                let crv = value.get("crv")?.as_str()?;
                let x = get("x")?;
                let y = get("y")?;
                match crv {
                    "P-256" if x.len() == 32 && y.len() == 32 => KeyMaterial::P256 { x, y },
                    "P-384" if x.len() == 48 && y.len() == 48 => KeyMaterial::P384 { x, y },
                    _ => return None,
                }
            }
            _ => return None,
        };
        Some(AnyJwk { kid, alg, key })
    }

    /// Parse a JWKS document (`{"keys": [...]}`), skipping unsupported keys.
    pub fn parse_jwks(value: &serde_json::Value) -> Vec<AnyJwk> {
        value
            .get("keys")
            .and_then(|k| k.as_array())
            .map(|keys| keys.iter().filter_map(AnyJwk::parse).collect())
            .unwrap_or_default()
    }

    /// Can this key verify signatures made with the given JWS `alg`?
    /// A JWK that declares its own `alg` (RFC 7517 §4.4) is restricted to it —
    /// except that the polymorphic `EdDSA` and the fully-specified `Ed25519`
    /// name the same Ed25519 operation, so an IdP JWKS declaring one accepts an
    /// assertion signed under the other.
    pub fn supports_alg(&self, alg: &str) -> bool {
        if let Some(declared) = &self.alg {
            if canonical_alg(declared) != canonical_alg(alg) {
                return false;
            }
        }
        matches!(
            (alg, &self.key),
            ("EdDSA" | "Ed25519", KeyMaterial::Ed25519 { .. })
                | ("RS256" | "RS384" | "RS512", KeyMaterial::Rsa { .. })
                | ("ES256", KeyMaterial::P256 { .. })
                | ("ES384", KeyMaterial::P384 { .. })
        )
    }

    /// Verify a JWS signature over `message`.
    pub fn verify(&self, alg: &str, message: &[u8], signature: &[u8]) -> Result<(), String> {
        use ring::signature as rs;
        match (alg, &self.key) {
            ("EdDSA" | "Ed25519", KeyMaterial::Ed25519 { x }) => {
                rs::UnparsedPublicKey::new(&rs::ED25519, x)
                    .verify(message, signature)
                    .map_err(|_| "Ed25519 signature verification failed".into())
            }
            ("RS256", KeyMaterial::Rsa { n, e }) => {
                rsa_verify(&rs::RSA_PKCS1_2048_8192_SHA256, n, e, message, signature)
            }
            ("RS384", KeyMaterial::Rsa { n, e }) => {
                rsa_verify(&rs::RSA_PKCS1_2048_8192_SHA384, n, e, message, signature)
            }
            ("RS512", KeyMaterial::Rsa { n, e }) => {
                rsa_verify(&rs::RSA_PKCS1_2048_8192_SHA512, n, e, message, signature)
            }
            ("ES256", KeyMaterial::P256 { x, y }) => {
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend_from_slice(x);
                point.extend_from_slice(y);
                rs::UnparsedPublicKey::new(&rs::ECDSA_P256_SHA256_FIXED, &point)
                    .verify(message, signature)
                    .map_err(|_| "ES256 signature verification failed".into())
            }
            ("ES384", KeyMaterial::P384 { x, y }) => {
                let mut point = Vec::with_capacity(97);
                point.push(0x04);
                point.extend_from_slice(x);
                point.extend_from_slice(y);
                rs::UnparsedPublicKey::new(&rs::ECDSA_P384_SHA384_FIXED, &point)
                    .verify(message, signature)
                    .map_err(|_| "ES384 signature verification failed".into())
            }
            _ => Err(format!("key does not support alg {alg}")),
        }
    }
}

/// Fold the two spellings of the Ed25519 signature algorithm together so a
/// JWKS `alg` declaration and an assertion header `alg` compare equal when they
/// name the same operation. Other algorithm names pass through unchanged.
fn canonical_alg(alg: &str) -> &str {
    match alg {
        "EdDSA" => "Ed25519",
        other => other,
    }
}

fn rsa_verify(
    alg: &'static ring::signature::RsaParameters,
    n: &[u8],
    e: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    ring::signature::RsaPublicKeyComponents { n, e }
        .verify(alg, message, signature)
        .map_err(|_| "RSA signature verification failed".into())
}

/// The JWS algorithms accepted on an ID token. Both the polymorphic `EdDSA`
/// and the fully-specified `Ed25519` (RFC 9864) map to Ed25519 keys; IdPs
/// may use either. `none` is never among them.
pub const SUPPORTED_ALGS: [&str; 7] = [
    "EdDSA", "Ed25519", "RS256", "RS384", "RS512", "ES256", "ES384",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7515 Appendix A.2 — RS256 test vector.
    #[test]
    fn rfc7515_a2_rs256() {
        let jwk: serde_json::Value = serde_json::json!({
            "kty": "RSA",
            "n": "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
            "e": "AQAB"
        });
        let key = AnyJwk::parse(&jwk).unwrap();
        let signing_input = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let sig = b64::decode(
            "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw",
        )
        .unwrap();
        key.verify("RS256", signing_input.as_bytes(), &sig).unwrap();
        // Tampered input must fail.
        assert!(key
            .verify("RS256", b"eyJhbGciOiJSUzI1NiJ9.tampered", &sig)
            .is_err());
    }

    /// RFC 7515 Appendix A.3 — ES256 test vector (fixed r||s signature).
    #[test]
    fn rfc7515_a3_es256() {
        let jwk: serde_json::Value = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        });
        let key = AnyJwk::parse(&jwk).unwrap();
        let signing_input = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let sig = b64::decode(
            "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q",
        )
        .unwrap();
        assert_eq!(sig.len(), 64);
        key.verify("ES256", signing_input.as_bytes(), &sig).unwrap();
        assert!(key
            .verify("ES256", b"eyJhbGciOiJFUzI1NiJ9.tampered", &sig)
            .is_err());
    }

    #[test]
    fn ed25519_via_anyjwk() {
        let sk = aauth_core::jwk::generate_signing_key();
        let jwk_core = aauth_core::jwk::Jwk::from_verifying_key(&sk.verifying_key());
        let value = serde_json::to_value(&jwk_core).unwrap();
        let key = AnyJwk::parse(&value).unwrap();
        use ed25519_dalek::Signer;
        let msg = b"hello identity provider";
        let sig = sk.sign(msg);
        // Both the polymorphic `EdDSA` and the fully-specified `Ed25519`
        // identifiers are accepted from third-party IdPs.
        key.verify("EdDSA", msg, &sig.to_bytes()).unwrap();
        key.verify("Ed25519", msg, &sig.to_bytes()).unwrap();
        assert!(key.verify("EdDSA", b"other", &sig.to_bytes()).is_err());
        assert!(key.supports_alg("Ed25519"));
    }

    #[test]
    fn jwks_parsing_skips_unsupported() {
        let jwks = serde_json::json!({"keys": [
            {"kty": "RSA", "n": "AQAB", "e": "AQAB", "kid": "r1"},
            {"kty": "oct", "k": "secret"},
            {"kty": "EC", "crv": "P-521", "x": "AA", "y": "AA"},
            {"kty": "OKP", "crv": "Ed25519",
             "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "e1"}
        ]});
        let keys = AnyJwk::parse_jwks(&jwks);
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().any(|k| k.kid.as_deref() == Some("e1")));
    }
}
