//! Relational storage: plain SQL over SQLite. Postgres is a later driver
//! behind the same schema and the same method set.
//!
//! One connection behind a mutex; every operation is a handful of indexed
//! statements on a small database, so they run inline. Nothing here holds
//! the lock across an await. WAL mode and a busy timeout make a concurrent
//! CLI (`psd person add` against a running server) safe.
//!
//! Invariants enforced here rather than in handlers:
//! - `agent_binding` PRIMARY KEY (iss, sub): one agent, exactly one person
//!   ([`Store::bind_agent`] refuses to move an *active* binding).
//! - `directed_sub` UNIQUE(sub) and UNIQUE(person, audience).
//! - one-time tokens (enrolment) are consumed atomically.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::passkey::{NewCredential, StoredCredential};

const SCHEMA: &str = include_str!("schema.sql");
/// v1: the M1–M7 schema. v2: person.status / person.tenant, person_identity,
/// oidc_login (OIDC person login). Older databases are migrated in `open`.
pub const SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Clone)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "storage: {}", self.0)
    }
}
impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError(e.to_string())
    }
}

impl From<StoreError> for crate::problem::ApiError {
    fn from(e: StoreError) -> Self {
        crate::problem::ApiError::server_error(e.to_string())
    }
}

pub type SResult<T> = Result<T, StoreError>;

pub struct Store {
    conn: Mutex<Connection>,
    /// Set when `open` migrated an older schema, so startup can say so —
    /// a silent migration is the one thing an operator watching a roll
    /// wants to see confirmed.
    pub migrated_from: Option<i64>,
}

// ------------------------------------------------------------------ records

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub id: String,
    pub display_name: String,
    pub user_handle: Vec<u8>,
    pub created_at: u64,
    /// "active" or "deactivated".
    pub status: String,
    /// Organisational context from the identity provider, if any.
    pub tenant: Option<String>,
}

impl Person {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

/// An identity at an OpenID Connect provider linked to a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub idp_iss: String,
    pub idp_sub: String,
    pub person_id: String,
    pub email: Option<String>,
    pub linked_at: u64,
    pub last_login_at: Option<u64>,
}

/// One OIDC sign-in attempt, as taken (spent) by the callback.
#[derive(Debug, Clone)]
pub struct OidcLogin {
    pub state_hash: String,
    pub nonce_hash: String,
    pub code_verifier: String,
    pub next: String,
    pub link_person_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub person_id: String,
    pub stored: StoredCredential,
    pub nickname: Option<String>,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub person_id: String,
    pub csrf: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub agent_iss: String,
    pub agent_sub: String,
    pub person_id: String,
    pub status: String,
    pub platform: Option<String>,
    pub device: Option<String>,
    pub ap_name: Option<String>,
    pub ap_logo_uri: Option<String>,
    pub bound_at: u64,
    pub revoked_at: Option<u64>,
}

impl Binding {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

/// Display values recorded with a binding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BindingDisplay {
    pub platform: Option<String>,
    pub device: Option<String>,
    pub ap_name: Option<String>,
    pub ap_logo_uri: Option<String>,
}

/// Outcome of [`Store::bind_agent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// New tuple, now bound to this person.
    Created,
    /// Already bound to this person (display values refreshed).
    Existing,
    /// Was revoked; re-bound (possibly to a different person).
    Rebound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub id: String,
    pub kind: String,
    pub agent_iss: String,
    pub agent_sub: String,
    pub person_id: Option<String>,
    pub payload: serde_json::Value,
    pub state: String,
    /// `true` while the interaction code is still presentable.
    pub code_live: bool,
    pub result: Option<serde_json::Value>,
    pub created_at: u64,
    pub expires_at: u64,
    pub decided_at: Option<u64>,
}

impl Pending {
    pub fn is_open(&self) -> bool {
        self.state == "pending" || self.state == "interacting"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    pub id: String,
    pub person_id: String,
    pub agent_iss: String,
    pub agent_sub: String,
    pub audience: String,
    pub kind: String,
    pub scope: Option<String>,
    pub granted_at: u64,
    pub expires_at: Option<u64>,
}

/// The retained record of an issued person token (the retention obligation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonTokenRecord {
    pub jti: String,
    pub person_id: String,
    pub agent_iss: String,
    pub agent_sub: String,
    pub ps: String,
    pub sub: String,
    pub aud: String,
    pub mission_s256: Option<String>,
    pub tenant: Option<String>,
    pub iat: u64,
    pub exp: u64,
    pub purge_after: u64,
}

/// The record of an issued auth token (for outbound revocation, M5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthTokenRecord {
    pub jti: String,
    /// `None` when we issued it; the Access Server's issuer when we provided
    /// it after federation.
    pub iss: Option<String>,
    pub person_id: String,
    pub agent_iss: String,
    pub agent_sub: String,
    pub aud: String,
    pub sub: String,
    pub scope: Option<String>,
    pub mission_s256: Option<String>,
    pub iat: u64,
    pub exp: u64,
    pub revoked_at: Option<u64>,
}

/// A mission: the immutable approved blob plus lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mission {
    pub s256: String,
    pub owner_iss: String,
    pub owner_sub: String,
    pub person_id: String,
    /// The exact bytes `s256` was computed over.
    pub blob: Vec<u8>,
    pub approved_at: u64,
    pub expires_at: Option<u64>,
    pub state: String,
    pub termination_reason: Option<String>,
}

impl Mission {
    pub fn is_active(&self) -> bool {
        self.state == "active"
    }
    pub fn blob_json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.blob).unwrap_or(serde_json::Value::Null)
    }
}

/// One entry of a mission's log (accepted updates, completion, decisions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissionLogEntry {
    pub seq: u64,
    pub kind: String,
    pub body: Vec<u8>,
    pub s256: String,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub at: u64,
    pub person_id: Option<String>,
    pub actor: String,
    pub action: String,
    pub subject: Option<String>,
    pub detail: serde_json::Value,
}

fn now() -> u64 {
    aauth_core::now_unix()
}

fn sha256_hex(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in d {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn u(v: i64) -> u64 {
    v.max(0) as u64
}

impl Store {
    /// Open (creating and migrating) the database at `path`; `":memory:"`
    /// gives a private throwaway database.
    pub fn open(path: &str) -> SResult<Store> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        if path != ":memory:" {
            conn.pragma_update(None, "journal_mode", "WAL")?;
        }
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        let mut migrated_from: Option<i64> = None;
        let version: Option<i64> = conn
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        match version {
            None => {
                conn.execute(
                    "INSERT INTO schema_version(version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )?;
            }
            Some(v) if v == SCHEMA_VERSION => {}
            Some(1) => {
                // v1 → v2: two nullable-or-defaulted columns on person; the
                // new tables were created by the CREATE IF NOT EXISTS above.
                conn.execute_batch(
                    "ALTER TABLE person ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
                     ALTER TABLE person ADD COLUMN tenant TEXT;
                     UPDATE schema_version SET version = 2;",
                )?;
                migrated_from = Some(1);
            }
            Some(v) => {
                return Err(StoreError(format!(
                    "database schema version {v} is not supported by this build (expects \
                     {SCHEMA_VERSION})"
                )))
            }
        }
        Ok(Store {
            conn: Mutex::new(conn),
            migrated_from,
        })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> SResult<T> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        f(&conn).map_err(StoreError::from)
    }

    fn with_tx<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction) -> rusqlite::Result<T>,
    ) -> SResult<T> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    // ------------------------------------------------------------- persons

    const PERSON_SELECT: &'static str =
        "SELECT id, display_name, user_handle, created_at, status, tenant FROM person";

    pub fn create_person(&self, display_name: &str) -> SResult<Person> {
        let person = Person {
            id: format!("p-{}", aauth_core::rand_id(16)),
            display_name: display_name.to_string(),
            user_handle: crate::passkey::new_user_handle(),
            created_at: now(),
            status: "active".into(),
            tenant: None,
        };
        self.with(|c| {
            c.execute(
                "INSERT INTO person(id, display_name, user_handle, created_at, status) \
                 VALUES (?1, ?2, ?3, ?4, 'active')",
                params![
                    person.id,
                    person.display_name,
                    person.user_handle,
                    person.created_at as i64
                ],
            )
        })?;
        Ok(person)
    }

    fn row_person(r: &rusqlite::Row) -> rusqlite::Result<Person> {
        Ok(Person {
            id: r.get(0)?,
            display_name: r.get(1)?,
            user_handle: r.get(2)?,
            created_at: u(r.get(3)?),
            status: r.get(4)?,
            tenant: r.get(5)?,
        })
    }

    /// Deactivate or reactivate a person. Returns false if unknown.
    pub fn set_person_status(&self, id: &str, status: &str) -> SResult<bool> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE person SET status = ?2 WHERE id = ?1",
                params![id, status],
            )
        })?;
        Ok(n == 1)
    }

    /// Record (or clear) the person's organisational tenant.
    pub fn set_person_tenant(&self, id: &str, tenant: Option<&str>) -> SResult<()> {
        self.with(|c| {
            c.execute(
                "UPDATE person SET tenant = ?2 WHERE id = ?1",
                params![id, tenant],
            )
        })?;
        Ok(())
    }

    /// Every session of a person (offboarding: log them out everywhere).
    pub fn delete_sessions_for_person(&self, person_id: &str) -> SResult<usize> {
        self.with(|c| {
            c.execute(
                "DELETE FROM session WHERE person_id = ?1",
                params![person_id],
            )
        })
    }

    // ----------------------------------------------------- OIDC identities

    fn row_identity(r: &rusqlite::Row) -> rusqlite::Result<Identity> {
        Ok(Identity {
            idp_iss: r.get(0)?,
            idp_sub: r.get(1)?,
            person_id: r.get(2)?,
            email: r.get(3)?,
            linked_at: u(r.get(4)?),
            last_login_at: r.get::<_, Option<i64>>(5)?.map(u),
        })
    }

    const IDENTITY_SELECT: &'static str = "SELECT idp_iss, idp_sub, person_id, email, \
                                          linked_at, last_login_at FROM person_identity";

    pub fn identity(&self, idp_iss: &str, idp_sub: &str) -> SResult<Option<Identity>> {
        self.with(|c| {
            c.query_row(
                &format!(
                    "{} WHERE idp_iss = ?1 AND idp_sub = ?2",
                    Self::IDENTITY_SELECT
                ),
                params![idp_iss, idp_sub],
                Self::row_identity,
            )
            .optional()
        })
    }

    pub fn identities_for_person(&self, person_id: &str) -> SResult<Vec<Identity>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "{} WHERE person_id = ?1 ORDER BY linked_at",
                Self::IDENTITY_SELECT
            ))?;
            let rows = st.query_map(params![person_id], Self::row_identity)?;
            rows.collect()
        })
    }

    /// Link an identity to a person. `Ok(false)` when that identity is
    /// already linked to a *different* person (the PRIMARY KEY holds).
    pub fn link_identity(
        &self,
        person_id: &str,
        idp_iss: &str,
        idp_sub: &str,
        email: Option<&str>,
    ) -> SResult<bool> {
        self.with_tx(|tx| {
            let owner: Option<String> = tx
                .query_row(
                    "SELECT person_id FROM person_identity WHERE idp_iss = ?1 AND idp_sub = ?2",
                    params![idp_iss, idp_sub],
                    |r| r.get(0),
                )
                .optional()?;
            match owner {
                Some(o) if o != person_id => Ok(false),
                Some(_) => Ok(true),
                None => {
                    tx.execute(
                        "INSERT INTO person_identity(idp_iss, idp_sub, person_id, email, linked_at) \
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![idp_iss, idp_sub, person_id, email, now() as i64],
                    )?;
                    Ok(true)
                }
            }
        })
    }

    /// Note a sign-in through an identity (and refresh its display email).
    pub fn touch_identity(&self, idp_iss: &str, idp_sub: &str, email: Option<&str>) -> SResult<()> {
        self.with(|c| {
            c.execute(
                "UPDATE person_identity SET last_login_at = ?3, email = COALESCE(?4, email) \
                 WHERE idp_iss = ?1 AND idp_sub = ?2",
                params![idp_iss, idp_sub, now() as i64, email],
            )
        })?;
        Ok(())
    }

    // ------------------------------------------------------- OIDC logins

    /// Start a sign-in attempt; returns the plaintext id for the cookie.
    /// `state` and `nonce` are stored hashed.
    pub fn create_oidc_login(
        &self,
        state: &str,
        nonce: &str,
        code_verifier: &str,
        next: &str,
        link_person_id: Option<&str>,
        ttl_secs: u64,
    ) -> SResult<String> {
        let id = aauth_core::rand_token(192);
        let n = now();
        self.with(|c| {
            c.execute(
                "INSERT INTO oidc_login(id_hash, state_hash, nonce_hash, code_verifier, next, \
                 link_person_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    sha256_hex(&id),
                    sha256_hex(state),
                    sha256_hex(nonce),
                    code_verifier,
                    next,
                    link_person_id,
                    n as i64,
                    (n + ttl_secs) as i64
                ],
            )
        })?;
        Ok(id)
    }

    /// Spend a sign-in attempt: returns the row if it was open (unused and
    /// unexpired) and marks it used in the same transaction, so a callback
    /// URL is good exactly once whatever happens after.
    pub fn take_oidc_login(&self, id: &str) -> SResult<Option<OidcLogin>> {
        let h = sha256_hex(id);
        self.with_tx(|tx| {
            let row: Option<OidcLogin> = tx
                .query_row(
                    "SELECT state_hash, nonce_hash, code_verifier, next, link_person_id \
                     FROM oidc_login WHERE id_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
                    params![h, now() as i64],
                    |r| {
                        Ok(OidcLogin {
                            state_hash: r.get(0)?,
                            nonce_hash: r.get(1)?,
                            code_verifier: r.get(2)?,
                            next: r.get(3)?,
                            link_person_id: r.get(4)?,
                        })
                    },
                )
                .optional()?;
            if row.is_some() {
                tx.execute(
                    "UPDATE oidc_login SET used_at = ?2 WHERE id_hash = ?1",
                    params![h, now() as i64],
                )?;
            }
            Ok(row)
        })
    }

    pub fn purge_oidc_logins(&self) -> SResult<usize> {
        self.with(|c| {
            c.execute(
                "DELETE FROM oidc_login WHERE expires_at <= ?1 OR used_at IS NOT NULL",
                params![now() as i64],
            )
        })
    }

    pub fn get_person(&self, id: &str) -> SResult<Option<Person>> {
        self.with(|c| {
            c.query_row(
                &format!("{} WHERE id = ?1", Self::PERSON_SELECT),
                params![id],
                Self::row_person,
            )
            .optional()
        })
    }

    pub fn list_persons(&self) -> SResult<Vec<Person>> {
        self.with(|c| {
            let mut st = c.prepare(&format!("{} ORDER BY created_at", Self::PERSON_SELECT))?;
            let rows = st.query_map([], Self::row_person)?;
            rows.collect()
        })
    }

    // --------------------------------------------------------- credentials

    pub fn add_credential(
        &self,
        person_id: &str,
        cred: &NewCredential,
        nickname: Option<&str>,
    ) -> SResult<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO passkey_credential(cred_id, person_id, static_state, dynamic_state, \
                 transports, nickname, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    cred.cred_id,
                    person_id,
                    cred.static_state,
                    cred.dynamic_state,
                    cred.transports as i64,
                    nickname,
                    now() as i64
                ],
            )
        })?;
        Ok(())
    }

    fn row_credential(r: &rusqlite::Row) -> rusqlite::Result<Credential> {
        Ok(Credential {
            person_id: r.get(1)?,
            stored: StoredCredential {
                cred_id: r.get(0)?,
                user_handle: r.get(8)?,
                static_state: r.get(2)?,
                dynamic_state: r.get(3)?,
            },
            nickname: r.get(5)?,
            created_at: u(r.get(6)?),
            last_used_at: r.get::<_, Option<i64>>(7)?.map(u),
        })
    }

    const CRED_SELECT: &'static str = "SELECT c.cred_id, c.person_id, c.static_state, \
        c.dynamic_state, c.transports, c.nickname, c.created_at, c.last_used_at, p.user_handle \
        FROM passkey_credential c JOIN person p ON p.id = c.person_id";

    pub fn credential(&self, cred_id: &[u8]) -> SResult<Option<Credential>> {
        self.with(|c| {
            c.query_row(
                &format!("{} WHERE c.cred_id = ?1", Self::CRED_SELECT),
                params![cred_id],
                Self::row_credential,
            )
            .optional()
        })
    }

    pub fn credentials_for_person(&self, person_id: &str) -> SResult<Vec<Credential>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "{} WHERE c.person_id = ?1 ORDER BY c.created_at",
                Self::CRED_SELECT
            ))?;
            let rows = st.query_map(params![person_id], Self::row_credential)?;
            rows.collect()
        })
    }

    pub fn touch_credential(&self, cred_id: &[u8], dynamic_state: Option<&[u8]>) -> SResult<()> {
        self.with(|c| {
            match dynamic_state {
                Some(d) => c.execute(
                    "UPDATE passkey_credential SET dynamic_state = ?2, last_used_at = ?3 WHERE cred_id = ?1",
                    params![cred_id, d, now() as i64],
                ),
                None => c.execute(
                    "UPDATE passkey_credential SET last_used_at = ?2 WHERE cred_id = ?1",
                    params![cred_id, now() as i64],
                ),
            }
        })?;
        Ok(())
    }

    // ----------------------------------------------------------- enrolment

    /// Create a one-time enrolment token for `person_id`; returns the
    /// plaintext token (only ever available here).
    pub fn create_enrolment(&self, person_id: &str, ttl_secs: u64) -> SResult<String> {
        let token = aauth_core::rand_token(192);
        let n = now();
        self.with(|c| {
            c.execute(
                "INSERT INTO enrolment(token_hash, person_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![sha256_hex(&token), person_id, n as i64, (n + ttl_secs) as i64],
            )
        })?;
        Ok(token)
    }

    /// Look up an unexpired, unused enrolment token without consuming it.
    pub fn peek_enrolment(&self, token: &str) -> SResult<Option<String>> {
        let h = sha256_hex(token);
        self.with(|c| {
            c.query_row(
                "SELECT person_id FROM enrolment WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
                params![h, now() as i64],
                |r| r.get(0),
            )
            .optional()
        })
    }

    /// Consume an enrolment token atomically; returns the person id if it was
    /// valid, unused and unexpired.
    pub fn take_enrolment(&self, token: &str) -> SResult<Option<String>> {
        let h = sha256_hex(token);
        self.with_tx(|tx| {
            let person: Option<String> = tx
                .query_row(
                    "SELECT person_id FROM enrolment WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
                    params![h, now() as i64],
                    |r| r.get(0),
                )
                .optional()?;
            if person.is_some() {
                tx.execute(
                    "UPDATE enrolment SET used_at = ?2 WHERE token_hash = ?1",
                    params![h, now() as i64],
                )?;
            }
            Ok(person)
        })
    }

    // ------------------------------------------------------------ sessions

    /// Create a session; returns the plaintext session id (cookie value) and
    /// the CSRF token.
    pub fn create_session(&self, person_id: &str, ttl_secs: u64) -> SResult<(String, String)> {
        let sid = aauth_core::rand_token(192);
        let csrf = aauth_core::rand_token(128);
        let n = now();
        self.with(|c| {
            c.execute(
                "INSERT INTO session(id_hash, person_id, csrf, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![sha256_hex(&sid), person_id, csrf, n as i64, (n + ttl_secs) as i64],
            )
        })?;
        Ok((sid, csrf))
    }

    pub fn get_session(&self, sid: &str) -> SResult<Option<Session>> {
        let h = sha256_hex(sid);
        self.with(|c| {
            c.query_row(
                "SELECT person_id, csrf, created_at, expires_at FROM session WHERE id_hash = ?1 AND expires_at > ?2",
                params![h, now() as i64],
                |r| {
                    Ok(Session {
                        person_id: r.get(0)?,
                        csrf: r.get(1)?,
                        created_at: u(r.get(2)?),
                        expires_at: u(r.get(3)?),
                    })
                },
            )
            .optional()
        })
    }

    pub fn delete_session(&self, sid: &str) -> SResult<()> {
        let h = sha256_hex(sid);
        self.with(|c| c.execute("DELETE FROM session WHERE id_hash = ?1", params![h]))?;
        Ok(())
    }

    pub fn purge_expired_sessions(&self) -> SResult<usize> {
        self.with(|c| {
            c.execute(
                "DELETE FROM session WHERE expires_at <= ?1",
                params![now() as i64],
            )
        })
    }

    // ------------------------------------------------------------ bindings

    fn row_binding(r: &rusqlite::Row) -> rusqlite::Result<Binding> {
        Ok(Binding {
            agent_iss: r.get(0)?,
            agent_sub: r.get(1)?,
            person_id: r.get(2)?,
            status: r.get(3)?,
            platform: r.get(4)?,
            device: r.get(5)?,
            ap_name: r.get(6)?,
            ap_logo_uri: r.get(7)?,
            bound_at: u(r.get(8)?),
            revoked_at: r.get::<_, Option<i64>>(9)?.map(u),
        })
    }

    const BINDING_SELECT: &'static str = "SELECT agent_iss, agent_sub, person_id, status, \
        platform, device, ap_name, ap_logo_uri, bound_at, revoked_at FROM agent_binding";

    pub fn binding(&self, agent_iss: &str, agent_sub: &str) -> SResult<Option<Binding>> {
        self.with(|c| {
            c.query_row(
                &format!(
                    "{} WHERE agent_iss = ?1 AND agent_sub = ?2",
                    Self::BINDING_SELECT
                ),
                params![agent_iss, agent_sub],
                Self::row_binding,
            )
            .optional()
        })
    }

    pub fn bindings_for_person(&self, person_id: &str) -> SResult<Vec<Binding>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "{} WHERE person_id = ?1 ORDER BY bound_at DESC",
                Self::BINDING_SELECT
            ))?;
            let rows = st.query_map(params![person_id], Self::row_binding)?;
            rows.collect()
        })
    }

    /// Bind `(agent_iss, agent_sub)` to `person_id`, enforcing the invariant:
    /// an *active* binding to a different person is refused (the caller gets
    /// `Err(BoundToOther)`), a revoked one may be re-bound, an existing one to
    /// the same person is refreshed.
    pub fn bind_agent(
        &self,
        agent_iss: &str,
        agent_sub: &str,
        person_id: &str,
        display: &BindingDisplay,
    ) -> SResult<Result<BindOutcome, BoundToOther>> {
        self.with_tx(|tx| {
            let existing: Option<(String, String)> = tx
                .query_row(
                    "SELECT person_id, status FROM agent_binding WHERE agent_iss = ?1 AND agent_sub = ?2",
                    params![agent_iss, agent_sub],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match existing {
                None => {
                    tx.execute(
                        "INSERT INTO agent_binding(agent_iss, agent_sub, person_id, status, platform, \
                         device, ap_name, ap_logo_uri, bound_at) VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?6, ?7, ?8)",
                        params![
                            agent_iss, agent_sub, person_id, display.platform, display.device,
                            display.ap_name, display.ap_logo_uri, now() as i64
                        ],
                    )?;
                    Ok(Ok(BindOutcome::Created))
                }
                Some((owner, status)) if status == "active" && owner == person_id => {
                    tx.execute(
                        "UPDATE agent_binding SET platform = COALESCE(?3, platform), device = COALESCE(?4, device), \
                         ap_name = COALESCE(?5, ap_name), ap_logo_uri = COALESCE(?6, ap_logo_uri) \
                         WHERE agent_iss = ?1 AND agent_sub = ?2",
                        params![agent_iss, agent_sub, display.platform, display.device, display.ap_name, display.ap_logo_uri],
                    )?;
                    Ok(Ok(BindOutcome::Existing))
                }
                Some((owner, status)) if status == "active" => Ok(Err(BoundToOther { owner })),
                Some(_) => {
                    tx.execute(
                        "UPDATE agent_binding SET person_id = ?3, status = 'active', platform = ?4, device = ?5, \
                         ap_name = ?6, ap_logo_uri = ?7, bound_at = ?8, revoked_at = NULL \
                         WHERE agent_iss = ?1 AND agent_sub = ?2",
                        params![
                            agent_iss, agent_sub, person_id, display.platform, display.device,
                            display.ap_name, display.ap_logo_uri, now() as i64
                        ],
                    )?;
                    Ok(Ok(BindOutcome::Rebound))
                }
            }
        })
    }

    /// Revoke a binding. Returns whether an active binding existed.
    pub fn revoke_binding(&self, agent_iss: &str, agent_sub: &str) -> SResult<bool> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE agent_binding SET status = 'revoked', revoked_at = ?3 \
                 WHERE agent_iss = ?1 AND agent_sub = ?2 AND status = 'active'",
                params![agent_iss, agent_sub, now() as i64],
            )
        })?;
        Ok(n > 0)
    }

    // ------------------------------------------------------------- pending

    fn row_pending(r: &rusqlite::Row) -> rusqlite::Result<Pending> {
        Ok(Pending {
            id: r.get(0)?,
            kind: r.get(1)?,
            agent_iss: r.get(2)?,
            agent_sub: r.get(3)?,
            person_id: r.get(4)?,
            payload: serde_json::from_str(&r.get::<_, String>(5)?)
                .unwrap_or(serde_json::Value::Null),
            state: r.get(6)?,
            code_live: r.get::<_, Option<String>>(7)?.is_some(),
            result: r
                .get::<_, Option<String>>(8)?
                .and_then(|s| serde_json::from_str(&s).ok()),
            created_at: u(r.get(9)?),
            expires_at: u(r.get(10)?),
            decided_at: r.get::<_, Option<i64>>(11)?.map(u),
        })
    }

    const PENDING_SELECT: &'static str =
        "SELECT id, kind, agent_iss, agent_sub, person_id, payload, \
        state, code_hash, result, created_at, expires_at, decided_at FROM pending_request";

    /// Create a pending request; `code_hash` is the hash of the interaction
    /// code (unique while live).
    #[allow(clippy::too_many_arguments)]
    pub fn create_pending(
        &self,
        kind: &str,
        agent_iss: &str,
        agent_sub: &str,
        person_id: Option<&str>,
        payload: &serde_json::Value,
        code_hash: &str,
        ttl_secs: u64,
    ) -> SResult<Pending> {
        let id = format!("pr-{}", aauth_core::rand_token(128));
        let n = now();
        self.with(|c| {
            c.execute(
                "INSERT INTO pending_request(id, kind, agent_iss, agent_sub, person_id, payload, state, \
                 code_hash, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8, ?9)",
                params![id, kind, agent_iss, agent_sub, person_id, payload.to_string(), code_hash,
                        n as i64, (n + ttl_secs) as i64],
            )
        })?;
        Ok(Pending {
            id,
            kind: kind.into(),
            agent_iss: agent_iss.into(),
            agent_sub: agent_sub.into(),
            person_id: person_id.map(|s| s.to_string()),
            payload: payload.clone(),
            state: "pending".into(),
            code_live: true,
            result: None,
            created_at: n,
            expires_at: n + ttl_secs,
            decided_at: None,
        })
    }

    /// Fetch a pending request, lazily marking it `expired` when past its
    /// deadline while still open.
    pub fn pending(&self, id: &str) -> SResult<Option<Pending>> {
        let row = self.with(|c| {
            c.query_row(
                &format!("{} WHERE id = ?1", Self::PENDING_SELECT),
                params![id],
                Self::row_pending,
            )
            .optional()
        })?;
        match row {
            Some(mut p) if p.is_open() && p.expires_at <= now() => {
                self.with(|c| {
                    c.execute(
                        "UPDATE pending_request SET state = 'expired', code_hash = NULL WHERE id = ?1 \
                         AND state IN ('pending', 'interacting')",
                        params![id],
                    )
                })?;
                p.state = "expired".into();
                p.code_live = false;
                Ok(Some(p))
            }
            other => Ok(other),
        }
    }

    /// Resolve a live interaction code to its open pending request.
    pub fn pending_by_code(&self, code_hash: &str) -> SResult<Option<Pending>> {
        let id: Option<String> = self.with(|c| {
            c.query_row(
                "SELECT id FROM pending_request WHERE code_hash = ?1",
                params![code_hash],
                |r| r.get(0),
            )
            .optional()
        })?;
        match id {
            Some(id) => Ok(self.pending(&id)?.filter(|p| p.is_open())),
            None => Ok(None),
        }
    }

    /// Bind an open pending request to the person who arrived with its code
    /// (consuming the code) and mark it `interacting`. Returns the updated
    /// row, or `None` if it was not open / already claimed by someone else.
    pub fn claim_pending(&self, id: &str, person_id: &str) -> SResult<Option<Pending>> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE pending_request SET person_id = ?2, state = 'interacting', code_hash = NULL \
                 WHERE id = ?1 AND state IN ('pending', 'interacting') \
                 AND (person_id IS NULL OR person_id = ?2) AND expires_at > ?3",
                params![id, person_id, now() as i64],
            )
        })?;
        if n == 0 {
            return Ok(None);
        }
        self.pending(id)
    }

    /// Record the person's decision. Only an open request can be decided.
    pub fn decide_pending(
        &self,
        id: &str,
        state: &str,
        result: Option<&serde_json::Value>,
    ) -> SResult<bool> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE pending_request SET state = ?2, result = ?3, code_hash = NULL, decided_at = ?4 \
                 WHERE id = ?1 AND state IN ('pending', 'interacting')",
                params![id, state, result.map(|v| v.to_string()), now() as i64],
            )
        })?;
        Ok(n > 0)
    }

    /// Replace the stored result of an approved request (federation state).
    pub fn update_pending_result(&self, id: &str, result: &serde_json::Value) -> SResult<()> {
        self.with(|c| {
            c.execute(
                "UPDATE pending_request SET result = ?2 WHERE id = ?1 AND state = 'approved'",
                params![id, result.to_string()],
            )
        })?;
        Ok(())
    }

    /// Mark an approved result as delivered to the agent (single delivery).
    pub fn mark_delivered(&self, id: &str) -> SResult<bool> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE pending_request SET state = 'delivered', result = NULL WHERE id = ?1 AND state = 'approved'",
                params![id],
            )
        })?;
        Ok(n > 0)
    }

    /// Open requests claimed by this person (for the dashboard).
    pub fn pending_for_person(&self, person_id: &str) -> SResult<Vec<Pending>> {
        let rows = self.with(|c| {
            let mut st = c.prepare(&format!(
                "{} WHERE person_id = ?1 AND state IN ('pending', 'interacting') AND expires_at > ?2 \
                 ORDER BY created_at DESC",
                Self::PENDING_SELECT
            ))?;
            let rows = st.query_map(params![person_id, now() as i64], Self::row_pending)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })?;
        Ok(rows)
    }

    /// Open requests nobody has claimed yet (operator listing).
    pub fn unclaimed_pending(&self) -> SResult<Vec<Pending>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "{} WHERE person_id IS NULL AND state IN ('pending', 'interacting') AND expires_at > ?1 \
                 ORDER BY created_at DESC",
                Self::PENDING_SELECT
            ))?;
            let rows = st.query_map(params![now() as i64], Self::row_pending)?;
            rows.collect()
        })
    }

    /// Delete decided/expired requests older than `age_secs` (housekeeping).
    pub fn purge_pending(&self, age_secs: u64) -> SResult<usize> {
        let cutoff = now().saturating_sub(age_secs) as i64;
        self.with(|c| {
            c.execute(
                "DELETE FROM pending_request WHERE (state NOT IN ('pending', 'interacting') AND \
                 COALESCE(decided_at, expires_at) <= ?1) OR (expires_at <= ?1)",
                params![cutoff],
            )
        })
    }

    // ------------------------------------------------------------- consent

    fn row_consent(r: &rusqlite::Row) -> rusqlite::Result<Consent> {
        Ok(Consent {
            id: r.get(0)?,
            person_id: r.get(1)?,
            agent_iss: r.get(2)?,
            agent_sub: r.get(3)?,
            audience: r.get(4)?,
            kind: r.get(5)?,
            scope: r.get(6)?,
            granted_at: u(r.get(7)?),
            expires_at: r.get::<_, Option<i64>>(8)?.map(u),
        })
    }

    /// An unrevoked, unexpired consent for (person, agent, audience, kind).
    pub fn find_consent(
        &self,
        person_id: &str,
        agent_iss: &str,
        agent_sub: &str,
        audience: &str,
        kind: &str,
    ) -> SResult<Option<Consent>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, person_id, agent_iss, agent_sub, audience, kind, scope, granted_at, expires_at \
                 FROM consent WHERE person_id = ?1 AND agent_iss = ?2 AND agent_sub = ?3 AND audience = ?4 \
                 AND kind = ?5 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?6) \
                 ORDER BY granted_at DESC LIMIT 1",
                params![person_id, agent_iss, agent_sub, audience, kind, now() as i64],
                Self::row_consent,
            )
            .optional()
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn grant_consent(
        &self,
        person_id: &str,
        agent_iss: &str,
        agent_sub: &str,
        audience: &str,
        kind: &str,
        scope: Option<&str>,
        expires_at: Option<u64>,
    ) -> SResult<Consent> {
        let c = Consent {
            id: format!("c-{}", aauth_core::rand_id(16)),
            person_id: person_id.into(),
            agent_iss: agent_iss.into(),
            agent_sub: agent_sub.into(),
            audience: audience.into(),
            kind: kind.into(),
            scope: scope.map(|s| s.to_string()),
            granted_at: now(),
            expires_at,
        };
        self.with(|conn| {
            conn.execute(
                "INSERT INTO consent(id, person_id, agent_iss, agent_sub, audience, kind, scope, granted_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![c.id, c.person_id, c.agent_iss, c.agent_sub, c.audience, c.kind, c.scope,
                        c.granted_at as i64, c.expires_at.map(|e| e as i64)],
            )
        })?;
        Ok(c)
    }

    /// Revoke every consent this person gave to an agent (binding revocation).
    pub fn revoke_consents_for_agent(
        &self,
        person_id: &str,
        agent_iss: &str,
        agent_sub: &str,
    ) -> SResult<usize> {
        self.with(|c| {
            c.execute(
                "UPDATE consent SET revoked_at = ?4 WHERE person_id = ?1 AND agent_iss = ?2 AND agent_sub = ?3 \
                 AND revoked_at IS NULL",
                params![person_id, agent_iss, agent_sub, now() as i64],
            )
        })
    }

    pub fn consents_for_person(&self, person_id: &str) -> SResult<Vec<Consent>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, person_id, agent_iss, agent_sub, audience, kind, scope, granted_at, expires_at \
                 FROM consent WHERE person_id = ?1 AND revoked_at IS NULL ORDER BY granted_at DESC",
            )?;
            let rows = st.query_map(params![person_id], Self::row_consent)?;
            rows.collect()
        })
    }

    // -------------------------------------------------------- directed subs

    /// The directed `sub` for (person, audience): the stored value if one
    /// exists, else `derive()` stored under UNIQUE(sub) / UNIQUE(person, aud).
    pub fn directed_sub(
        &self,
        person_id: &str,
        audience: &str,
        derive: impl FnOnce() -> String,
    ) -> SResult<String> {
        self.with_tx(|tx| {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT sub FROM directed_sub WHERE person_id = ?1 AND audience = ?2",
                    params![person_id, audience],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(s) = existing {
                return Ok(s);
            }
            let sub = derive();
            tx.execute(
                "INSERT INTO directed_sub(person_id, audience, sub, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![person_id, audience, sub, now() as i64],
            )?;
            Ok(sub)
        })
    }

    /// The person (and audience) behind a directed `sub` we issued.
    pub fn person_for_sub(&self, sub: &str) -> SResult<Option<(String, String)>> {
        self.with(|c| {
            c.query_row(
                "SELECT person_id, audience FROM directed_sub WHERE sub = ?1",
                params![sub],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
        })
    }

    // -------------------------------------------------- person token records

    /// Retain the record of an issued person token, and opportunistically drop
    /// records past their `purge_after`.
    pub fn record_person_token(&self, rec: &PersonTokenRecord) -> SResult<()> {
        self.with_tx(|tx| {
            tx.execute(
                "DELETE FROM person_token_record WHERE purge_after < ?1",
                params![now() as i64],
            )?;
            tx.execute(
                "INSERT INTO person_token_record(jti, person_id, agent_iss, agent_sub, ps, sub, aud, \
                 mission_s256, tenant, iat, exp, purge_after) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![rec.jti, rec.person_id, rec.agent_iss, rec.agent_sub, rec.ps, rec.sub, rec.aud,
                        rec.mission_s256, rec.tenant, rec.iat as i64, rec.exp as i64, rec.purge_after as i64],
            )?;
            Ok(())
        })
    }

    /// The retained record for a `jti`, if still within its retention window.
    pub fn person_token_record(&self, jti: &str) -> SResult<Option<PersonTokenRecord>> {
        self.with(|c| {
            c.query_row(
                "SELECT jti, person_id, agent_iss, agent_sub, ps, sub, aud, mission_s256, tenant, iat, exp, purge_after \
                 FROM person_token_record WHERE jti = ?1 AND purge_after >= ?2",
                params![jti, now() as i64],
                |r| {
                    Ok(PersonTokenRecord {
                        jti: r.get(0)?,
                        person_id: r.get(1)?,
                        agent_iss: r.get(2)?,
                        agent_sub: r.get(3)?,
                        ps: r.get(4)?,
                        sub: r.get(5)?,
                        aud: r.get(6)?,
                        mission_s256: r.get(7)?,
                        tenant: r.get(8)?,
                        iat: u(r.get(9)?),
                        exp: u(r.get(10)?),
                        purge_after: u(r.get(11)?),
                    })
                },
            )
            .optional()
        })
    }

    /// Distinct audiences this agent obtained person tokens for since `since`
    /// (the SHOULD rate-limit on distinct `resource` values).
    pub fn distinct_audiences_since(
        &self,
        agent_iss: &str,
        agent_sub: &str,
        since: u64,
    ) -> SResult<u64> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(DISTINCT aud) FROM person_token_record WHERE agent_iss = ?1 AND agent_sub = ?2 AND iat >= ?3",
                params![agent_iss, agent_sub, since as i64],
                |r| r.get::<_, i64>(0),
            )
            .map(u)
        })
    }

    /// Whether this agent already holds a (retained, unexpired) person token
    /// for `aud` — used so the distinct-resource limit never blocks a resource
    /// the agent already uses.
    pub fn agent_has_token_for(
        &self,
        agent_iss: &str,
        agent_sub: &str,
        aud: &str,
    ) -> SResult<bool> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM person_token_record WHERE agent_iss = ?1 AND agent_sub = ?2 AND aud = ?3",
                params![agent_iss, agent_sub, aud],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
        })
    }

    pub fn purge_person_token_records(&self) -> SResult<usize> {
        self.with(|c| {
            c.execute(
                "DELETE FROM person_token_record WHERE purge_after < ?1",
                params![now() as i64],
            )
        })
    }

    /// Every scope this person has granted this agent at `audience` (union of
    /// unrevoked, unexpired `auth` consents).
    pub fn granted_scopes(
        &self,
        person_id: &str,
        agent_iss: &str,
        agent_sub: &str,
        audience: &str,
    ) -> SResult<std::collections::BTreeSet<String>> {
        let rows: Vec<Option<String>> = self.with(|c| {
            let mut st = c.prepare(
                "SELECT scope FROM consent WHERE person_id = ?1 AND agent_iss = ?2 AND agent_sub = ?3 \
                 AND audience = ?4 AND kind = 'auth' AND revoked_at IS NULL \
                 AND (expires_at IS NULL OR expires_at > ?5)",
            )?;
            let rows = st.query_map(
                params![person_id, agent_iss, agent_sub, audience, now() as i64],
                |r| r.get(0),
            )?;
            rows.collect()
        })?;
        let mut out = std::collections::BTreeSet::new();
        for scope in rows.into_iter().flatten() {
            for s in scope.split_whitespace() {
                out.insert(s.to_string());
            }
        }
        Ok(out)
    }

    // ---------------------------------------------------- auth token records

    pub fn record_auth_token(&self, rec: &AuthTokenRecord) -> SResult<()> {
        self.with_tx(|tx| {
            // Housekeeping: forget tokens that expired more than a day ago.
            tx.execute(
                "DELETE FROM auth_token_record WHERE exp < ?1",
                params![now().saturating_sub(86_400) as i64],
            )?;
            tx.execute(
                "INSERT INTO auth_token_record(jti, iss, person_id, agent_iss, agent_sub, aud, sub, scope, \
                 mission_s256, iat, exp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![rec.jti, rec.iss, rec.person_id, rec.agent_iss, rec.agent_sub, rec.aud, rec.sub,
                        rec.scope, rec.mission_s256, rec.iat as i64, rec.exp as i64],
            )?;
            Ok(())
        })
    }

    fn row_auth_token(r: &rusqlite::Row) -> rusqlite::Result<AuthTokenRecord> {
        Ok(AuthTokenRecord {
            jti: r.get(0)?,
            iss: r.get(11)?,
            person_id: r.get(1)?,
            agent_iss: r.get(2)?,
            agent_sub: r.get(3)?,
            aud: r.get(4)?,
            sub: r.get(5)?,
            scope: r.get(6)?,
            mission_s256: r.get(7)?,
            iat: u(r.get(8)?),
            exp: u(r.get(9)?),
            revoked_at: r.get::<_, Option<i64>>(10)?.map(u),
        })
    }

    const AUTH_SELECT: &'static str =
        "SELECT jti, person_id, agent_iss, agent_sub, aud, sub, scope, \
        mission_s256, iat, exp, revoked_at, iss FROM auth_token_record";

    /// Unexpired, unrevoked auth tokens issued for an agent (to revoke).
    pub fn live_auth_tokens_for_agent(
        &self,
        agent_iss: &str,
        agent_sub: &str,
    ) -> SResult<Vec<AuthTokenRecord>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "{} WHERE agent_iss = ?1 AND agent_sub = ?2 AND exp > ?3 AND revoked_at IS NULL",
                Self::AUTH_SELECT
            ))?;
            let rows = st.query_map(
                params![agent_iss, agent_sub, now() as i64],
                Self::row_auth_token,
            )?;
            rows.collect()
        })
    }

    pub fn auth_token_record(&self, jti: &str) -> SResult<Option<AuthTokenRecord>> {
        self.with(|c| {
            c.query_row(
                &format!("{} WHERE jti = ?1", Self::AUTH_SELECT),
                params![jti],
                Self::row_auth_token,
            )
            .optional()
        })
    }

    pub fn mark_auth_token_revoked(&self, jti: &str) -> SResult<bool> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE auth_token_record SET revoked_at = ?2 WHERE jti = ?1 AND revoked_at IS NULL",
                params![jti, now() as i64],
            )
        })?;
        Ok(n > 0)
    }

    // ------------------------------------------------- agent token tracking

    /// Remember that this agent token signed a request (upsert; expired rows
    /// are dropped opportunistically).
    pub fn note_agent_token_seen(
        &self,
        iss: &str,
        jti: &str,
        agent_sub: &str,
        exp: u64,
    ) -> SResult<()> {
        self.with_tx(|tx| {
            tx.execute(
                "DELETE FROM agent_token_seen WHERE exp < ?1",
                params![now().saturating_sub(3600) as i64],
            )?;
            tx.execute(
                "INSERT INTO agent_token_seen(iss, jti, agent_sub, exp, first_seen) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(iss, jti) DO NOTHING",
                params![iss, jti, agent_sub, exp as i64, now() as i64],
            )?;
            Ok(())
        })
    }

    /// The agent behind a seen token, if we have seen it.
    pub fn agent_token_seen(&self, iss: &str, jti: &str) -> SResult<Option<(String, u64)>> {
        self.with(|c| {
            c.query_row(
                "SELECT agent_sub, exp FROM agent_token_seen WHERE iss = ?1 AND jti = ?2",
                params![iss, jti],
                |r| Ok((r.get::<_, String>(0)?, u(r.get(1)?))),
            )
            .optional()
        })
    }

    /// Record an inbound revocation. Idempotent. Returns whether it was new.
    pub fn revoke_agent_token(&self, iss: &str, jti: &str, purge_after: u64) -> SResult<bool> {
        self.with_tx(|tx| {
            tx.execute(
                "DELETE FROM revoked_agent_token WHERE purge_after < ?1",
                params![now() as i64],
            )?;
            let n = tx.execute(
                "INSERT INTO revoked_agent_token(iss, jti, revoked_at, purge_after) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(iss, jti) DO NOTHING",
                params![iss, jti, now() as i64, purge_after as i64],
            )?;
            Ok(n > 0)
        })
    }

    pub fn is_agent_token_revoked(&self, iss: &str, jti: &str) -> SResult<bool> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM revoked_agent_token WHERE iss = ?1 AND jti = ?2 AND purge_after >= ?3",
                params![iss, jti, now() as i64],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
        })
    }

    // ------------------------------------------------------------ missions

    fn row_mission(r: &rusqlite::Row) -> rusqlite::Result<Mission> {
        Ok(Mission {
            s256: r.get(0)?,
            owner_iss: r.get(1)?,
            owner_sub: r.get(2)?,
            person_id: r.get(3)?,
            blob: r.get(4)?,
            approved_at: u(r.get(5)?),
            expires_at: r.get::<_, Option<i64>>(6)?.map(u),
            state: r.get(7)?,
            termination_reason: r.get(8)?,
        })
    }

    const MISSION_SELECT: &'static str = "SELECT mission_s256, owner_iss, owner_sub, person_id, \
        blob, approved_at, expires_at, state, termination_reason FROM mission";

    pub fn create_mission(&self, m: &Mission) -> SResult<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO mission(mission_s256, owner_iss, owner_sub, person_id, blob, approved_at, \
                 expires_at, state, termination_reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![m.s256, m.owner_iss, m.owner_sub, m.person_id, m.blob, m.approved_at as i64,
                        m.expires_at.map(|e| e as i64), m.state, m.termination_reason],
            )
        })?;
        Ok(())
    }

    /// Fetch a mission. Every decision path compares the current time to
    /// `expires_at`, so an active mission past it is reported (and recorded)
    /// as terminated with reason `expired` here, on read.
    pub fn mission(&self, s256: &str) -> SResult<Option<Mission>> {
        let row = self.with(|c| {
            c.query_row(
                &format!("{} WHERE mission_s256 = ?1", Self::MISSION_SELECT),
                params![s256],
                Self::row_mission,
            )
            .optional()
        })?;
        match row {
            Some(mut m) if m.is_active() && m.expires_at.map(|e| e <= now()).unwrap_or(false) => {
                self.terminate_mission(s256, "expired")?;
                m.state = "terminated".into();
                m.termination_reason = Some("expired".into());
                Ok(Some(m))
            }
            other => Ok(other),
        }
    }

    /// Terminate a mission (never back to active). Returns whether it was active.
    pub fn terminate_mission(&self, s256: &str, reason: &str) -> SResult<bool> {
        let n = self.with(|c| {
            c.execute(
                "UPDATE mission SET state = 'terminated', termination_reason = ?2 \
                 WHERE mission_s256 = ?1 AND state = 'active'",
                params![s256, reason],
            )
        })?;
        Ok(n > 0)
    }

    pub fn missions_for_person(&self, person_id: &str) -> SResult<Vec<Mission>> {
        let rows = self.with(|c| {
            let mut st = c.prepare(&format!(
                "{} WHERE person_id = ?1 ORDER BY approved_at DESC",
                Self::MISSION_SELECT
            ))?;
            let rows = st.query_map(params![person_id], Self::row_mission)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })?;
        // Apply lazy expiry consistently.
        let mut out = Vec::with_capacity(rows.len());
        for m in rows {
            if let Some(m) = self.mission(&m.s256)? {
                out.push(m);
            }
        }
        Ok(out)
    }

    /// Append to a mission's log; returns the entry (with its sequence number
    /// and the digest of the exact bytes stored).
    pub fn append_mission_log(
        &self,
        s256: &str,
        kind: &str,
        body: &[u8],
    ) -> SResult<MissionLogEntry> {
        let digest = {
            let d = Sha256::digest(body);
            aauth_core::b64::encode(&d)
        };
        let at = now();
        let seq = self.with_tx(|tx| {
            let next: i64 = tx.query_row(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM mission_log WHERE mission_s256 = ?1",
                params![s256],
                |r| r.get(0),
            )?;
            tx.execute(
                "INSERT INTO mission_log(mission_s256, seq, kind, body, s256, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![s256, next, kind, body, digest, at as i64],
            )?;
            Ok(next)
        })?;
        Ok(MissionLogEntry {
            seq: seq as u64,
            kind: kind.into(),
            body: body.to_vec(),
            s256: digest,
            at,
        })
    }

    pub fn mission_log(&self, s256: &str) -> SResult<Vec<MissionLogEntry>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT seq, kind, body, s256, at FROM mission_log WHERE mission_s256 = ?1 ORDER BY seq",
            )?;
            let rows = st.query_map(params![s256], |r| {
                Ok(MissionLogEntry {
                    seq: u(r.get(0)?),
                    kind: r.get(1)?,
                    body: r.get(2)?,
                    s256: r.get(3)?,
                    at: u(r.get(4)?),
                })
            })?;
            rows.collect()
        })
    }

    /// Unexpired, unrevoked auth tokens issued under a mission (to revoke).
    pub fn live_auth_tokens_for_mission(&self, s256: &str) -> SResult<Vec<AuthTokenRecord>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "{} WHERE mission_s256 = ?1 AND exp > ?2 AND revoked_at IS NULL",
                Self::AUTH_SELECT
            ))?;
            let rows = st.query_map(params![s256, now() as i64], Self::row_auth_token)?;
            rows.collect()
        })
    }

    // --------------------------------------------------------------- audit

    pub fn audit(
        &self,
        person_id: Option<&str>,
        actor: &str,
        action: &str,
        subject: Option<&str>,
        detail: &serde_json::Value,
    ) -> SResult<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO audit(id, at, person_id, actor, action, subject, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    aauth_core::rand_token(96),
                    now() as i64,
                    person_id,
                    actor,
                    action,
                    subject,
                    detail.to_string()
                ],
            )
        })?;
        Ok(())
    }

    pub fn recent_audit(&self, person_id: Option<&str>, limit: usize) -> SResult<Vec<AuditRow>> {
        self.with(|c| {
            let map = |r: &rusqlite::Row| -> rusqlite::Result<AuditRow> {
                Ok(AuditRow {
                    at: u(r.get(0)?),
                    person_id: r.get(1)?,
                    actor: r.get(2)?,
                    action: r.get(3)?,
                    subject: r.get(4)?,
                    detail: serde_json::from_str(&r.get::<_, String>(5)?)
                        .unwrap_or(serde_json::Value::Null),
                })
            };
            match person_id {
                Some(p) => {
                    let mut st = c.prepare(
                        "SELECT at, person_id, actor, action, subject, detail FROM audit \
                         WHERE person_id = ?1 ORDER BY at DESC, rowid DESC LIMIT ?2",
                    )?;
                    let rows = st.query_map(params![p, limit as i64], map)?;
                    rows.collect()
                }
                None => {
                    let mut st = c.prepare(
                        "SELECT at, person_id, actor, action, subject, detail FROM audit \
                         ORDER BY at DESC, rowid DESC LIMIT ?1",
                    )?;
                    let rows = st.query_map(params![limit as i64], map)?;
                    rows.collect()
                }
            }
        })
    }
}

/// The agent is actively bound to another person (the invariant refused).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundToOther {
    pub owner: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open(":memory:").unwrap()
    }

    #[test]
    fn schema_opens_and_reopens() {
        let s = store();
        assert!(s.list_persons().unwrap().is_empty());
        // A second open on the same file path would re-run the idempotent
        // schema; :memory: is per-connection so just check version handling.
        s.with(|c| c.execute("UPDATE schema_version SET version = 99", []))
            .unwrap();
        // Simulate reopening: build a Store over the same connection contents
        // is not possible with :memory:, so exercise the version check
        // directly.
        let v: i64 = s
            .with(|c| c.query_row("SELECT version FROM schema_version", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(v, 99);
    }

    #[test]
    fn persons_and_credentials() {
        let s = store();
        let p = s.create_person("Alice").unwrap();
        assert_eq!(p.user_handle.len(), 64);
        assert_eq!(s.get_person(&p.id).unwrap().unwrap(), p);
        assert_eq!(s.list_persons().unwrap().len(), 1);

        let cred = NewCredential {
            cred_id: vec![1; 16],
            user_handle: p.user_handle.clone(),
            static_state: vec![2, 3],
            dynamic_state: vec![0; 7],
            transports: 4,
        };
        s.add_credential(&p.id, &cred, Some("laptop")).unwrap();
        // duplicate credential id is refused by the PRIMARY KEY
        assert!(s.add_credential(&p.id, &cred, None).is_err());
        let got = s.credential(&cred.cred_id).unwrap().unwrap();
        assert_eq!(got.person_id, p.id);
        assert_eq!(got.stored.user_handle, p.user_handle);
        assert_eq!(got.stored.static_state, vec![2, 3]);
        assert_eq!(got.nickname.as_deref(), Some("laptop"));
        assert!(got.last_used_at.is_none());
        s.touch_credential(&cred.cred_id, Some(&[9; 7])).unwrap();
        let got = s.credential(&cred.cred_id).unwrap().unwrap();
        assert_eq!(got.stored.dynamic_state, vec![9; 7]);
        assert!(got.last_used_at.is_some());
        assert_eq!(s.credentials_for_person(&p.id).unwrap().len(), 1);
        assert!(s.credential(&[7; 16]).unwrap().is_none());
    }

    #[test]
    fn enrolment_tokens_are_single_use_and_expire() {
        let s = store();
        let p = s.create_person("Alice").unwrap();
        let t = s.create_enrolment(&p.id, 600).unwrap();
        assert_eq!(
            s.peek_enrolment(&t).unwrap().as_deref(),
            Some(p.id.as_str())
        );
        assert_eq!(
            s.take_enrolment(&t).unwrap().as_deref(),
            Some(p.id.as_str())
        );
        assert!(s.take_enrolment(&t).unwrap().is_none(), "single use");
        assert!(s.peek_enrolment(&t).unwrap().is_none());
        assert!(s.take_enrolment("nope").unwrap().is_none());
        // expired
        let t2 = s.create_enrolment(&p.id, 0).unwrap();
        assert!(s.take_enrolment(&t2).unwrap().is_none());
    }

    #[test]
    fn sessions() {
        let s = store();
        let p = s.create_person("Alice").unwrap();
        let (sid, csrf) = s.create_session(&p.id, 3600).unwrap();
        let sess = s.get_session(&sid).unwrap().unwrap();
        assert_eq!(sess.person_id, p.id);
        assert_eq!(sess.csrf, csrf);
        assert!(s.get_session("nope").unwrap().is_none());
        s.delete_session(&sid).unwrap();
        assert!(s.get_session(&sid).unwrap().is_none());
        let (sid2, _) = s.create_session(&p.id, 0).unwrap();
        assert!(s.get_session(&sid2).unwrap().is_none(), "expired");
        assert_eq!(s.purge_expired_sessions().unwrap(), 1);
    }

    #[test]
    fn binding_invariant_one_agent_one_person() {
        let s = store();
        let alice = s.create_person("Alice").unwrap();
        let bob = s.create_person("Bob").unwrap();
        let disp = BindingDisplay {
            platform: Some("server".into()),
            ..Default::default()
        };
        assert_eq!(
            s.bind_agent("https://ap.example", "aauth:a@ap.example", &alice.id, &disp)
                .unwrap(),
            Ok(BindOutcome::Created)
        );
        // Same agent, same person → existing.
        assert_eq!(
            s.bind_agent(
                "https://ap.example",
                "aauth:a@ap.example",
                &alice.id,
                &BindingDisplay::default()
            )
            .unwrap(),
            Ok(BindOutcome::Existing)
        );
        // Same agent, different person → refused, and the row is untouched.
        assert_eq!(
            s.bind_agent("https://ap.example", "aauth:a@ap.example", &bob.id, &disp)
                .unwrap(),
            Err(BoundToOther {
                owner: alice.id.clone()
            })
        );
        let b = s
            .binding("https://ap.example", "aauth:a@ap.example")
            .unwrap()
            .unwrap();
        assert_eq!(b.person_id, alice.id);
        assert!(b.is_active());
        assert_eq!(b.platform.as_deref(), Some("server"));
        // Same `sub` at a *different* AP is a different agent entirely.
        assert_eq!(
            s.bind_agent(
                "https://other.example",
                "aauth:a@ap.example",
                &bob.id,
                &disp
            )
            .unwrap(),
            Ok(BindOutcome::Created)
        );
        // Revoke, then Bob may claim it.
        assert!(s
            .revoke_binding("https://ap.example", "aauth:a@ap.example")
            .unwrap());
        assert!(!s
            .revoke_binding("https://ap.example", "aauth:a@ap.example")
            .unwrap());
        assert!(!s
            .binding("https://ap.example", "aauth:a@ap.example")
            .unwrap()
            .unwrap()
            .is_active());
        assert_eq!(
            s.bind_agent("https://ap.example", "aauth:a@ap.example", &bob.id, &disp)
                .unwrap(),
            Ok(BindOutcome::Rebound)
        );
        let b = s
            .binding("https://ap.example", "aauth:a@ap.example")
            .unwrap()
            .unwrap();
        assert_eq!(b.person_id, bob.id);
        assert!(b.is_active());
        assert!(b.revoked_at.is_none());
        assert_eq!(s.bindings_for_person(&bob.id).unwrap().len(), 2);
        assert_eq!(s.bindings_for_person(&alice.id).unwrap().len(), 0);
    }

    #[test]
    fn pending_lifecycle() {
        let s = store();
        let p = s.create_person("Alice").unwrap();
        let payload = serde_json::json!({ "resource": "https://r.example" });
        let pr = s
            .create_pending(
                "person",
                "https://ap.example",
                "aauth:a@ap.example",
                None,
                &payload,
                "h1",
                600,
            )
            .unwrap();
        assert_eq!(pr.state, "pending");
        assert!(pr.code_live);
        assert!(pr.person_id.is_none());
        // code lookup, claim (consumes the code), decide
        assert_eq!(s.pending_by_code("h1").unwrap().unwrap().id, pr.id);
        assert!(s.pending_by_code("nope").unwrap().is_none());
        let claimed = s.claim_pending(&pr.id, &p.id).unwrap().unwrap();
        assert_eq!(claimed.state, "interacting");
        assert!(!claimed.code_live);
        assert_eq!(claimed.person_id.as_deref(), Some(p.id.as_str()));
        assert!(s.pending_by_code("h1").unwrap().is_none(), "code consumed");
        // another person cannot claim it now
        let bob = s.create_person("Bob").unwrap();
        assert!(s.claim_pending(&pr.id, &bob.id).unwrap().is_none());
        // same person may re-claim (page reload)
        assert!(s.claim_pending(&pr.id, &p.id).unwrap().is_some());
        assert_eq!(s.pending_for_person(&p.id).unwrap().len(), 1);
        assert!(s
            .decide_pending(
                &pr.id,
                "approved",
                Some(&serde_json::json!({ "person_token": "t" }))
            )
            .unwrap());
        assert!(
            !s.decide_pending(&pr.id, "denied", None).unwrap(),
            "already decided"
        );
        let got = s.pending(&pr.id).unwrap().unwrap();
        assert_eq!(got.state, "approved");
        assert_eq!(got.result.unwrap()["person_token"], "t");
        assert!(got.decided_at.is_some());
        assert!(s.mark_delivered(&pr.id).unwrap());
        assert!(!s.mark_delivered(&pr.id).unwrap());
        assert!(s.pending(&pr.id).unwrap().unwrap().result.is_none());
        assert_eq!(s.pending_for_person(&p.id).unwrap().len(), 0);
        // expiry is lazy on read
        let pr2 = s
            .create_pending(
                "person",
                "https://ap.example",
                "aauth:b@ap.example",
                None,
                &payload,
                "h2",
                0,
            )
            .unwrap();
        let got = s.pending(&pr2.id).unwrap().unwrap();
        assert_eq!(got.state, "expired");
        assert!(s.pending_by_code("h2").unwrap().is_none());
        assert!(s.claim_pending(&pr2.id, &p.id).unwrap().is_none());
        // duplicate code hash is refused
        assert!(s
            .create_pending(
                "person",
                "https://ap.example",
                "aauth:c@ap.example",
                None,
                &payload,
                "h3",
                600
            )
            .is_ok());
        assert!(s
            .create_pending(
                "person",
                "https://ap.example",
                "aauth:d@ap.example",
                None,
                &payload,
                "h3",
                600
            )
            .is_err());
        assert!(s.purge_pending(0).unwrap() >= 1);
    }

    #[test]
    fn consent_and_directed_sub_and_retention() {
        let s = store();
        let p = s.create_person("Alice").unwrap();
        assert!(s
            .find_consent(
                &p.id,
                "https://ap.example",
                "aauth:a@ap.example",
                "https://r.example",
                "person"
            )
            .unwrap()
            .is_none());
        s.grant_consent(
            &p.id,
            "https://ap.example",
            "aauth:a@ap.example",
            "https://r.example",
            "person",
            None,
            None,
        )
        .unwrap();
        assert!(s
            .find_consent(
                &p.id,
                "https://ap.example",
                "aauth:a@ap.example",
                "https://r.example",
                "person"
            )
            .unwrap()
            .is_some());
        // an expired consent does not count
        s.grant_consent(
            &p.id,
            "https://ap.example",
            "aauth:a@ap.example",
            "https://old.example",
            "person",
            None,
            Some(1),
        )
        .unwrap();
        assert!(s
            .find_consent(
                &p.id,
                "https://ap.example",
                "aauth:a@ap.example",
                "https://old.example",
                "person"
            )
            .unwrap()
            .is_none());
        assert_eq!(s.consents_for_person(&p.id).unwrap().len(), 2);
        assert_eq!(
            s.revoke_consents_for_agent(&p.id, "https://ap.example", "aauth:a@ap.example")
                .unwrap(),
            2
        );
        assert!(s
            .find_consent(
                &p.id,
                "https://ap.example",
                "aauth:a@ap.example",
                "https://r.example",
                "person"
            )
            .unwrap()
            .is_none());

        // directed sub: derived once, stored, stable
        let a = s
            .directed_sub(&p.id, "https://r.example", || "sub-A".into())
            .unwrap();
        let b = s
            .directed_sub(&p.id, "https://r.example", || "sub-B".into())
            .unwrap();
        assert_eq!(a, "sub-A");
        assert_eq!(b, "sub-A", "stored value is authoritative");
        // UNIQUE(sub): the same value for another (person, aud) is refused
        let bob = s.create_person("Bob").unwrap();
        assert!(s
            .directed_sub(&bob.id, "https://r.example", || "sub-A".into())
            .is_err());

        // retention
        let n = now();
        let rec = PersonTokenRecord {
            jti: "pt-1".into(),
            person_id: p.id.clone(),
            agent_iss: "https://ap.example".into(),
            agent_sub: "aauth:a@ap.example".into(),
            ps: "https://ps.example".into(),
            sub: "sub-A".into(),
            aud: "https://r.example".into(),
            mission_s256: None,
            tenant: None,
            iat: n,
            exp: n + 3600,
            purge_after: n + 7500,
        };
        s.record_person_token(&rec).unwrap();
        assert_eq!(s.person_token_record("pt-1").unwrap().unwrap(), rec);
        assert!(s.person_token_record("pt-x").unwrap().is_none());
        assert!(s
            .agent_has_token_for(
                "https://ap.example",
                "aauth:a@ap.example",
                "https://r.example"
            )
            .unwrap());
        assert!(!s
            .agent_has_token_for(
                "https://ap.example",
                "aauth:a@ap.example",
                "https://z.example"
            )
            .unwrap());
        assert_eq!(
            s.distinct_audiences_since("https://ap.example", "aauth:a@ap.example", n - 10)
                .unwrap(),
            1
        );
        // a record past purge_after is invisible and gets purged on the next insert
        let old = PersonTokenRecord {
            jti: "pt-old".into(),
            purge_after: n - 1,
            ..rec.clone()
        };
        s.record_person_token(&old).unwrap();
        assert!(s.person_token_record("pt-old").unwrap().is_none());
        let newer = PersonTokenRecord {
            jti: "pt-2".into(),
            aud: "https://r2.example".into(),
            ..rec.clone()
        };
        s.record_person_token(&newer).unwrap();
        assert_eq!(
            s.distinct_audiences_since("https://ap.example", "aauth:a@ap.example", n - 10)
                .unwrap(),
            2
        );
        let count: i64 = s
            .with(|c| c.query_row("SELECT COUNT(*) FROM person_token_record", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(count, 2, "pt-old was purged");
    }

    #[test]
    fn granted_scopes_and_auth_token_records() {
        let s = store();
        let p = s.create_person("Alice").unwrap();
        assert!(s
            .granted_scopes(
                &p.id,
                "https://ap.example",
                "aauth:a@ap.example",
                "https://r.example"
            )
            .unwrap()
            .is_empty());
        s.grant_consent(
            &p.id,
            "https://ap.example",
            "aauth:a@ap.example",
            "https://r.example",
            "auth",
            Some("read write"),
            None,
        )
        .unwrap();
        s.grant_consent(
            &p.id,
            "https://ap.example",
            "aauth:a@ap.example",
            "https://r.example",
            "auth",
            Some("admin"),
            Some(1),
        )
        .unwrap();
        s.grant_consent(
            &p.id,
            "https://ap.example",
            "aauth:a@ap.example",
            "https://r.example",
            "person",
            None,
            None,
        )
        .unwrap();
        let g = s
            .granted_scopes(
                &p.id,
                "https://ap.example",
                "aauth:a@ap.example",
                "https://r.example",
            )
            .unwrap();
        assert_eq!(
            g.into_iter().collect::<Vec<_>>(),
            vec!["read".to_string(), "write".to_string()],
            "expired admin excluded, person kind excluded"
        );
        let n = now();
        let rec = AuthTokenRecord {
            jti: "at-1".into(),
            iss: None,
            person_id: p.id.clone(),
            agent_iss: "https://ap.example".into(),
            agent_sub: "aauth:a@ap.example".into(),
            aud: "https://r.example".into(),
            sub: "S".into(),
            scope: Some("read".into()),
            mission_s256: None,
            iat: n,
            exp: n + 600,
            revoked_at: None,
        };
        s.record_auth_token(&rec).unwrap();
        assert_eq!(s.auth_token_record("at-1").unwrap().unwrap(), rec);
        assert_eq!(
            s.live_auth_tokens_for_agent("https://ap.example", "aauth:a@ap.example")
                .unwrap()
                .len(),
            1
        );
        assert!(s.mark_auth_token_revoked("at-1").unwrap());
        assert!(!s.mark_auth_token_revoked("at-1").unwrap());
        assert!(s
            .live_auth_tokens_for_agent("https://ap.example", "aauth:a@ap.example")
            .unwrap()
            .is_empty());
        assert!(s
            .auth_token_record("at-1")
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());
    }

    #[test]
    fn agent_token_seen_and_revoked() {
        let s = store();
        let n = now();
        assert!(s
            .agent_token_seen("https://ap.example", "j1")
            .unwrap()
            .is_none());
        s.note_agent_token_seen("https://ap.example", "j1", "aauth:a@ap.example", n + 600)
            .unwrap();
        s.note_agent_token_seen("https://ap.example", "j1", "aauth:a@ap.example", n + 600)
            .unwrap();
        assert_eq!(
            s.agent_token_seen("https://ap.example", "j1")
                .unwrap()
                .unwrap()
                .0,
            "aauth:a@ap.example"
        );
        assert!(!s
            .is_agent_token_revoked("https://ap.example", "j1")
            .unwrap());
        assert!(s
            .revoke_agent_token("https://ap.example", "j1", n + 600)
            .unwrap());
        assert!(
            !s.revoke_agent_token("https://ap.example", "j1", n + 600)
                .unwrap(),
            "idempotent"
        );
        assert!(s
            .is_agent_token_revoked("https://ap.example", "j1")
            .unwrap());
        // same jti at another issuer is a different token
        assert!(!s
            .is_agent_token_revoked("https://other.example", "j1")
            .unwrap());
        // a revocation past its purge horizon is forgotten
        s.revoke_agent_token("https://ap.example", "j-old", n - 1)
            .unwrap();
        assert!(!s
            .is_agent_token_revoked("https://ap.example", "j-old")
            .unwrap());
    }

    #[test]
    fn missions() {
        let s = store();
        let p = s.create_person("Alice").unwrap();
        let n = now();
        let m = Mission {
            s256: "abc".into(),
            owner_iss: "https://ap.example".into(),
            owner_sub: "aauth:a@ap.example".into(),
            person_id: p.id.clone(),
            blob: b"{\"description\":\"x\"}".to_vec(),
            approved_at: n,
            expires_at: Some(n + 600),
            state: "active".into(),
            termination_reason: None,
        };
        s.create_mission(&m).unwrap();
        assert!(s.create_mission(&m).is_err(), "s256 is the primary key");
        assert_eq!(s.mission("abc").unwrap().unwrap(), m);
        assert!(s.mission("nope").unwrap().is_none());
        assert_eq!(
            s.mission("abc").unwrap().unwrap().blob_json()["description"],
            "x"
        );
        // log entries are sequenced and digested
        let e1 = s.append_mission_log("abc", "update", b"first").unwrap();
        let e2 = s.append_mission_log("abc", "update", b"second").unwrap();
        assert_eq!((e1.seq, e2.seq), (1, 2));
        assert_ne!(e1.s256, e2.s256);
        assert_eq!(s.mission_log("abc").unwrap().len(), 2);
        // terminate is one-way
        assert!(s.terminate_mission("abc", "revoked").unwrap());
        assert!(!s.terminate_mission("abc", "completed").unwrap());
        let got = s.mission("abc").unwrap().unwrap();
        assert!(!got.is_active());
        assert_eq!(got.termination_reason.as_deref(), Some("revoked"));
        // lazy expiry on read
        let expired = Mission {
            s256: "old".into(),
            expires_at: Some(n - 1),
            ..m.clone()
        };
        s.create_mission(&expired).unwrap();
        let got = s.mission("old").unwrap().unwrap();
        assert_eq!(got.state, "terminated");
        assert_eq!(got.termination_reason.as_deref(), Some("expired"));
        assert_eq!(s.missions_for_person(&p.id).unwrap().len(), 2);
        // auth tokens under a mission
        s.record_auth_token(&AuthTokenRecord {
            jti: "at-m".into(),
            iss: None,
            person_id: p.id.clone(),
            agent_iss: m.owner_iss.clone(),
            agent_sub: m.owner_sub.clone(),
            aud: "https://r.example".into(),
            sub: "S".into(),
            scope: None,
            mission_s256: Some("abc".into()),
            iat: n,
            exp: n + 600,
            revoked_at: None,
        })
        .unwrap();
        assert_eq!(s.live_auth_tokens_for_mission("abc").unwrap().len(), 1);
        assert!(s.live_auth_tokens_for_mission("old").unwrap().is_empty());
    }

    #[test]
    fn audit_rows() {
        let s = store();
        let p = s.create_person("Alice").unwrap();
        s.audit(
            Some(&p.id),
            "agent:aauth:a@ap.example",
            "person_token_issued",
            Some("https://r.example"),
            &serde_json::json!({ "jti": "x" }),
        )
        .unwrap();
        s.audit(
            None,
            "system",
            "server_started",
            None,
            &serde_json::json!({}),
        )
        .unwrap();
        let all = s.recent_audit(None, 10).unwrap();
        assert_eq!(all.len(), 2);
        let mine = s.recent_audit(Some(&p.id), 10).unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].action, "person_token_issued");
        assert_eq!(mine[0].detail["jti"], "x");
    }

    #[test]
    fn v1_database_is_migrated_to_v2() {
        // A v1 database (no person.status / tenant, no identity tables) as
        // deployed by the first release: opening it must add the columns,
        // create the tables and bump the version, keeping the rows.
        let dir = std::env::temp_dir().join(format!("psd-store-mig-{}", aauth_core::rand_id(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v1.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version(version) VALUES (1);
                 CREATE TABLE person (id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
                   user_handle BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL);
                 INSERT INTO person(id, display_name, user_handle, created_at)
                   VALUES ('p-old', 'Old Alice', x'01', 1);",
            )
            .unwrap();
        }
        let s = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(s.migrated_from, Some(1));
        let v: i64 = s
            .with(|c| c.query_row("SELECT version FROM schema_version", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(v, 2);
        let p = s.get_person("p-old").unwrap().unwrap();
        assert_eq!(p.display_name, "Old Alice");
        assert!(p.is_active());
        assert_eq!(p.tenant, None);
        assert!(s.identity("https://idp", "x").unwrap().is_none());
        // Reopening a v2 database is a no-op.
        drop(s);
        let s = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(s.migrated_from, None);
        assert!(s.get_person("p-old").unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identities_link_once_and_status_tenant_round_trip() {
        let s = store();
        let a = s.create_person("Alice").unwrap();
        let b = s.create_person("Bob").unwrap();
        assert!(s
            .link_identity(&a.id, "https://idp", "sub-1", Some("alice@acme.example"))
            .unwrap());
        // Same identity, same person: fine. Same identity, another person: no.
        assert!(s
            .link_identity(&a.id, "https://idp", "sub-1", None)
            .unwrap());
        assert!(!s
            .link_identity(&b.id, "https://idp", "sub-1", None)
            .unwrap());
        let id = s.identity("https://idp", "sub-1").unwrap().unwrap();
        assert_eq!(id.person_id, a.id);
        assert_eq!(id.email.as_deref(), Some("alice@acme.example"));
        assert!(id.last_login_at.is_none());
        s.touch_identity("https://idp", "sub-1", Some("alice.new@acme.example"))
            .unwrap();
        let id = s.identity("https://idp", "sub-1").unwrap().unwrap();
        assert!(id.last_login_at.is_some());
        assert_eq!(id.email.as_deref(), Some("alice.new@acme.example"));
        assert_eq!(s.identities_for_person(&a.id).unwrap().len(), 1);
        assert!(s.identities_for_person(&b.id).unwrap().is_empty());
        // Status and tenant.
        s.set_person_tenant(&a.id, Some("acme")).unwrap();
        assert_eq!(
            s.get_person(&a.id).unwrap().unwrap().tenant.as_deref(),
            Some("acme")
        );
        assert!(s.set_person_status(&a.id, "deactivated").unwrap());
        assert!(!s.get_person(&a.id).unwrap().unwrap().is_active());
        assert!(!s.set_person_status("p-nobody", "deactivated").unwrap());
        let (sid, _) = s.create_session(&a.id, 600).unwrap();
        assert_eq!(s.delete_sessions_for_person(&a.id).unwrap(), 1);
        assert!(s.get_session(&sid).unwrap().is_none());
    }

    #[test]
    fn oidc_login_is_spent_once() {
        let s = store();
        let id = s
            .create_oidc_login("st", "nc", "verifier", "/next", None, 600)
            .unwrap();
        let row = s.take_oidc_login(&id).unwrap().unwrap();
        assert_eq!(row.state_hash, sha256_hex("st"));
        assert_eq!(row.nonce_hash, sha256_hex("nc"));
        assert_eq!(row.code_verifier, "verifier");
        assert_eq!(row.next, "/next");
        assert!(row.link_person_id.is_none());
        // Second presentation: spent.
        assert!(s.take_oidc_login(&id).unwrap().is_none());
        // Unknown and expired: nothing.
        assert!(s.take_oidc_login("nope").unwrap().is_none());
        let id2 = s.create_oidc_login("st", "nc", "v", "/", None, 0).unwrap();
        assert!(s.take_oidc_login(&id2).unwrap().is_none());
        assert!(s.purge_oidc_logins().unwrap() >= 2);
    }
}
