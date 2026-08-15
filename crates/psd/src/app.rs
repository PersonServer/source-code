//! Shared application state, built once at startup and handed to every
//! handler as `Arc<App>`. Everything here is immutable after construction
//! except the caches and the store, which carry their own locks.

use std::sync::Arc;

use aauth_core::now_unix;

use crate::audit::Audit;
use crate::config::Config;
use crate::httpc::EgressPolicy;
use crate::jwks_cache::JwksCache;
use crate::keys::KeySet;
use crate::passkey::Passkeys;
use crate::pending::PendingNotify;
use crate::reqctx::ReplayCache;
use crate::store::Store;
use crate::ui::Templates;

pub struct App {
    pub cfg: Config,
    pub keys: KeySet,
    pub store: Store,
    pub jwks_cache: JwksCache,
    /// Outbound admission policy, shared by discovery and (later) outbound
    /// revocation and webhooks so every egress obeys the same SSRF rules.
    pub egress: EgressPolicy,
    pub audit: Audit,
    pub replay: ReplayCache,
    /// Wake-ups for `Prefer: wait` long-polls on pending requests.
    pub pending_notify: PendingNotify,
    /// Failed interaction-code presentations per person, for the MUST
    /// rate-limit on code validation (§Interaction Code Format).
    pub code_attempts: CodeAttempts,
    /// `None` when the issuer host is an IP address (WebAuthn needs a domain
    /// RP ID); the UI then explains instead of failing obscurely.
    pub passkeys: Option<Passkeys>,
    pub templates: Templates,
    /// Pre-serialized well-known documents. Verification traffic hammers
    /// these; serialize once at startup.
    pub person_metadata_bytes: Vec<u8>,
    pub jwks_bytes: Vec<u8>,
    pub started_at: u64,
}

impl App {
    /// Build the application state. Fails fast on an unopenable audit log,
    /// database or template.
    pub fn new(cfg: Config, keys: KeySet) -> Result<Arc<App>, String> {
        let audit = Audit::new(cfg.audit_log_file.as_deref())?;
        let store = Store::open(&cfg.storage.path).map_err(|e| e.to_string())?;
        App::build(cfg, keys, audit, store)
    }

    pub fn build(
        cfg: Config,
        keys: KeySet,
        audit: Audit,
        store: Store,
    ) -> Result<Arc<App>, String> {
        let egress = EgressPolicy::from_config(cfg.insecure_dev_mode);
        let jwks_cache = JwksCache::new(egress.clone(), cfg.jwks_cross_origin_hosts.clone());
        let person_metadata_bytes =
            serde_json::to_vec(&crate::metadata::build_person_metadata(&cfg))
                .expect("serialize metadata");
        let jwks_bytes = serde_json::to_vec(&keys.jwks_json()).expect("serialize jwks");
        let templates = Templates::load(&cfg)?;
        let passkeys = Passkeys::new(&cfg.issuer).ok();
        Ok(Arc::new(App {
            cfg,
            keys,
            store,
            jwks_cache,
            egress,
            audit,
            replay: ReplayCache::new(),
            pending_notify: PendingNotify::new(),
            code_attempts: CodeAttempts::default(),
            passkeys,
            templates,
            person_metadata_bytes,
            jwks_bytes,
            started_at: now_unix(),
        }))
    }

    /// Record a decision: one structured audit line (stderr/file) and one row
    /// in the relational audit table for the dashboard.
    pub fn record(
        &self,
        person_id: Option<&str>,
        actor: &str,
        action: &str,
        subject: Option<&str>,
        detail: serde_json::Value,
    ) {
        let mut line = detail.clone();
        if let Some(obj) = line.as_object_mut() {
            obj.insert("actor".into(), actor.into());
            if let Some(p) = person_id {
                obj.insert("person_id".into(), p.into());
            }
            if let Some(s) = subject {
                obj.insert("subject".into(), s.into());
            }
        }
        self.audit.emit(action, line);
        if let Err(e) = self.store.audit(person_id, actor, action, subject, &detail) {
            eprintln!("audit row not written: {e}");
        }
    }
}

/// A small in-memory limiter: at most `limit` failed code presentations per
/// person per 10-minute window.
#[derive(Default)]
pub struct CodeAttempts {
    inner: std::sync::Mutex<std::collections::HashMap<String, (u32, u64)>>,
}

impl CodeAttempts {
    const WINDOW_SECS: u64 = 600;

    /// Whether `person_id` may attempt another code right now.
    pub fn allowed(&self, person_id: &str, limit: u32) -> bool {
        let now = now_unix();
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, (_, start)| now.saturating_sub(*start) < Self::WINDOW_SECS);
        m.get(person_id).map(|(n, _)| *n < limit).unwrap_or(true)
    }

    /// Record a failed presentation.
    pub fn failed(&self, person_id: &str) {
        let now = now_unix();
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let e = m.entry(person_id.to_string()).or_insert((0, now));
        e.0 += 1;
    }

    /// A success clears the counter.
    pub fn succeeded(&self, person_id: &str) {
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        m.remove(person_id);
    }
}
