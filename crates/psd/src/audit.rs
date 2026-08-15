//! Structured audit logging: one JSON object per line, to stderr and
//! (optionally) an append-only file. The Person Server is where a human is
//! held to a decision, and where an agent lying to us must leave a trace, so
//! every issuance, denial, binding change and tamper indication is emitted here
//! (and mirrored into the relational `audit` table for the dashboard).
//!
//! Events: `server_started`, `signature_rejected`, `person_token_issued`,
//! `person_token_denied`, `auth_token_issued`, `auth_token_denied`,
//! `agent_bound`, `binding_revoked`, `consent_granted`, `consent_denied`,
//! `agent_token_revoked`, `mission_stripping_suspected`, `mission_*`.
//!
//! Copied from apd (MIT OR Apache-2.0).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

pub struct Audit {
    file: Option<Mutex<File>>,
    /// Suppress the stderr copy (tests).
    quiet: bool,
}

impl Audit {
    pub fn new(path: Option<&str>) -> Result<Audit, String> {
        let file = match path {
            Some(p) => {
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .map_err(|e| format!("cannot open audit log {p}: {e}"))?;
                Some(Mutex::new(f))
            }
            None => None,
        };
        Ok(Audit { file, quiet: false })
    }

    /// An audit sink that writes nowhere — for in-process tests.
    #[cfg(test)]
    pub fn quiet() -> Audit {
        Audit {
            file: None,
            quiet: true,
        }
    }

    /// Emit an audit event. `fields` must be a JSON object.
    pub fn emit(&self, event: &str, mut fields: serde_json::Value) {
        let obj = fields
            .as_object_mut()
            .expect("audit fields must be an object");
        obj.insert("ts".into(), aauth_core::now_unix().into());
        obj.insert("event".into(), event.into());
        let line = serde_json::Value::Object(std::mem::take(obj)).to_string();
        if !self.quiet {
            eprintln!("audit {line}");
        }
        if let Some(file) = &self.file {
            if let Ok(mut f) = file.lock() {
                let _ = writeln!(f, "{line}");
            }
        }
    }
}
