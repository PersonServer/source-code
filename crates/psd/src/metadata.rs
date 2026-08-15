//! The `/.well-known/aauth-person.json` document (AAuth §Person Server
//! Metadata). Serialized once at startup — verifiers hammer it.
//!
//! Optional endpoints are advertised only when the feature is enabled *and*
//! implemented: presence of `mission_endpoint` is how a PS says it supports
//! missions, so an unimplemented endpoint must not appear.

use crate::config::Config;

pub fn build_person_metadata(cfg: &Config) -> serde_json::Value {
    let mut doc = serde_json::Map::new();
    let iss = &cfg.issuer;
    doc.insert("issuer".into(), iss.clone().into());
    doc.insert(
        "jwks_uri".into(),
        format!("{iss}/.well-known/jwks.json").into(),
    );
    // REQUIRED endpoints. The field is `auth_token_endpoint`; the older name
    // `token_endpoint` is what a verifier written against an earlier draft
    // would look for, and it must not appear.
    doc.insert("auth_token_endpoint".into(), format!("{iss}/token").into());
    doc.insert(
        "person_token_endpoint".into(),
        format!("{iss}/person").into(),
    );
    // Common metadata field: exactly the set of fully-specified JWS
    // algorithms our verifier accepts — neither a subset nor a superset — the
    // out-of-band twin of the `Accept-Signature-Alg` header. psd verifies
    // Ed25519 only.
    doc.insert(
        "accept_signature_algs".into(),
        serde_json::json!([aauth_core::jwk::ALG_ED25519]),
    );
    // RECOMMENDED: what this PS can assert. Shape A asserts recognition and
    // agency (`sub`) and nothing more; widen this only when a claim is
    // actually emitted.
    doc.insert("scopes_supported".into(), serde_json::json!(["openid"]));
    doc.insert("claims_supported".into(), serde_json::json!(["sub"]));
    for (name, value) in [
        ("name", &cfg.metadata.name),
        ("description", &cfg.metadata.description),
        ("logo_uri", &cfg.metadata.logo_uri),
        ("logo_dark_uri", &cfg.metadata.logo_dark_uri),
        ("documentation_uri", &cfg.metadata.documentation_uri),
        ("tos_uri", &cfg.metadata.tos_uri),
        ("policy_uri", &cfg.metadata.policy_uri),
    ] {
        if let Some(v) = value {
            doc.insert(name.into(), v.clone().into());
        }
    }
    // Where an Agent Provider revokes an agent token it issued (§Token
    // Revocation), and where our own tokens can be revoked by us.
    doc.insert("revocation_endpoint".into(), format!("{iss}/revoke").into());
    if cfg.missions.enabled {
        doc.insert("mission_endpoint".into(), format!("{iss}/mission").into());
    }
    serde_json::Value::Object(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(v: serde_json::Value) -> Config {
        let cfg: Config = serde_json::from_value(v).unwrap();
        cfg.validate().unwrap();
        cfg
    }

    #[test]
    fn required_fields_and_exact_algs() {
        let doc = build_person_metadata(&cfg(serde_json::json!({
            "issuer": "https://ps.example",
            "metadata": { "name": "PS", "description": "**md**" }
        })));
        assert_eq!(doc["issuer"], "https://ps.example");
        assert_eq!(doc["jwks_uri"], "https://ps.example/.well-known/jwks.json");
        assert_eq!(doc["auth_token_endpoint"], "https://ps.example/token");
        assert_eq!(doc["person_token_endpoint"], "https://ps.example/person");
        assert_eq!(doc["accept_signature_algs"], serde_json::json!(["Ed25519"]));
        assert_eq!(doc["name"], "PS");
        assert_eq!(doc["description"], "**md**");
        // The superseded field name must not appear.
        assert!(doc.get("token_endpoint").is_none());
        // Optional endpoints absent until implemented/enabled.
        assert_eq!(doc["revocation_endpoint"], "https://ps.example/revoke");
        for k in [
            "mission_endpoint",
            "interaction_endpoint",
            "permission_endpoint",
            "audit_endpoint",
        ] {
            assert!(doc.get(k).is_none(), "{k} must not be advertised");
        }
    }
}
