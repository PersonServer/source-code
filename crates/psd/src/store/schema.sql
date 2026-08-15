-- psd relational schema, v1.
--
-- Portability: TEXT ids, INTEGER unix seconds, BLOB opaque bytes; no SQLite-
-- only syntax outside PRAGMAs, so this is the same schema for Postgres later.
-- `person_id` is a real column everywhere from day one (shape A → C).

CREATE TABLE IF NOT EXISTS schema_version (
  version    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS person (
  id            TEXT PRIMARY KEY,
  display_name  TEXT NOT NULL,
  -- WebAuthn user.id (64 random bytes); what a passkey asserts.
  user_handle   BLOB NOT NULL UNIQUE,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS passkey_credential (
  cred_id        BLOB PRIMARY KEY,
  person_id      TEXT NOT NULL REFERENCES person(id),
  static_state   BLOB NOT NULL,   -- public key + registration extensions (opaque)
  dynamic_state  BLOB NOT NULL,   -- sign counter, UV/backup flags (opaque)
  transports     INTEGER NOT NULL,
  nickname       TEXT,
  created_at     INTEGER NOT NULL,
  last_used_at   INTEGER
);
CREATE INDEX IF NOT EXISTS passkey_credential_person ON passkey_credential(person_id);

-- One-time enrolment links (`psd person add` / `psd invite`). The token is
-- stored hashed; the plaintext is printed once.
CREATE TABLE IF NOT EXISTS enrolment (
  token_hash  TEXT PRIMARY KEY,
  person_id   TEXT NOT NULL REFERENCES person(id),
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);

-- Browser sessions. The cookie value is stored hashed.
CREATE TABLE IF NOT EXISTS session (
  id_hash     TEXT PRIMARY KEY,
  person_id   TEXT NOT NULL REFERENCES person(id),
  csrf        TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS session_expires ON session(expires_at);

-- The trust invariant: one agent, exactly one person. The PRIMARY KEY on
-- (iss, sub) — never sub alone — IS the enforcement. One row per agent
-- forever; revocation flips status; a later re-binding to another person
-- updates person_id and the audit table keeps the history.
CREATE TABLE IF NOT EXISTS agent_binding (
  agent_iss    TEXT NOT NULL,
  agent_sub    TEXT NOT NULL,
  person_id    TEXT NOT NULL REFERENCES person(id),
  status       TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  platform     TEXT,            -- agent-attested, display only
  device       TEXT,            -- agent-attested, display only
  ap_name      TEXT,            -- from the AP's metadata at binding time
  ap_logo_uri  TEXT,
  bound_at     INTEGER NOT NULL,
  revoked_at   INTEGER,
  PRIMARY KEY (agent_iss, agent_sub)
);
CREATE INDEX IF NOT EXISTS agent_binding_person ON agent_binding(person_id);

-- Directed identifiers: derived once, then authoritative. UNIQUE(sub) makes
-- "unique within the issuer" a guarantee rather than a probability.
CREATE TABLE IF NOT EXISTS directed_sub (
  person_id   TEXT NOT NULL REFERENCES person(id),
  audience    TEXT NOT NULL,
  sub         TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (person_id, audience)
);

-- The retention obligation (§Person Token Endpoint): answers resource-token
-- verification step 6. `purge_after` = exp + resource_token_max_age + slack;
-- rows past it are deleted opportunistically. Retention has a floor and a
-- ceiling: forget early and valid resource tokens are rejected, never forget
-- and the table grows without bound — so it is a column, not a cron job.
CREATE TABLE IF NOT EXISTS person_token_record (
  jti           TEXT PRIMARY KEY,
  person_id     TEXT NOT NULL,
  agent_iss     TEXT NOT NULL,
  agent_sub     TEXT NOT NULL,
  ps            TEXT NOT NULL,
  sub           TEXT NOT NULL,
  aud           TEXT NOT NULL,
  mission_s256  TEXT,
  tenant        TEXT,
  iat           INTEGER NOT NULL,
  exp           INTEGER NOT NULL,
  purge_after   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS person_token_record_purge ON person_token_record(purge_after);
CREATE INDEX IF NOT EXISTS person_token_record_agent ON person_token_record(agent_iss, agent_sub, iat);

-- Auth tokens we issued (iss NULL) or provided from an Access Server (iss =
-- the AS), so "revoke what you issued or provided for that agent" can reach
-- each resource's revocation endpoint with (iss, jti).
CREATE TABLE IF NOT EXISTS auth_token_record (
  jti           TEXT PRIMARY KEY,
  iss           TEXT,
  person_id     TEXT NOT NULL,
  agent_iss     TEXT NOT NULL,
  agent_sub     TEXT NOT NULL,
  aud           TEXT NOT NULL,
  sub           TEXT NOT NULL,
  scope         TEXT,
  mission_s256  TEXT,
  iat           INTEGER NOT NULL,
  exp           INTEGER NOT NULL,
  revoked_at    INTEGER
);
CREATE INDEX IF NOT EXISTS auth_token_record_agent ON auth_token_record(agent_iss, agent_sub, exp);

-- Agent tokens that have signed a request here: (iss, jti) → agent, exp. Lets
-- an inbound revocation of a jti find the agent whose auth tokens to revoke.
CREATE TABLE IF NOT EXISTS agent_token_seen (
  iss          TEXT NOT NULL,
  jti          TEXT NOT NULL,
  agent_sub    TEXT NOT NULL,
  exp          INTEGER NOT NULL,
  first_seen   INTEGER NOT NULL,
  PRIMARY KEY (iss, jti)
);

-- Inbound revocations of agent tokens, keyed by (iss, jti) — a jti is unique
-- only within its issuer. Kept until the token would have expired anyway.
CREATE TABLE IF NOT EXISTS revoked_agent_token (
  iss          TEXT NOT NULL,
  jti          TEXT NOT NULL,
  revoked_at   INTEGER NOT NULL,
  purge_after  INTEGER NOT NULL,
  PRIMARY KEY (iss, jti)
);

-- Consent decisions the person made, per (agent, audience, kind).
CREATE TABLE IF NOT EXISTS consent (
  id          TEXT PRIMARY KEY,
  person_id   TEXT NOT NULL REFERENCES person(id),
  agent_iss   TEXT NOT NULL,
  agent_sub   TEXT NOT NULL,
  audience    TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('person', 'auth')),
  scope       TEXT,
  granted_at  INTEGER NOT NULL,
  expires_at  INTEGER,
  revoked_at  INTEGER
);
CREATE INDEX IF NOT EXISTS consent_lookup ON consent(person_id, agent_iss, agent_sub, audience, kind);

-- Deferred (202) requests waiting on the person. `person_id` is NULL until a
-- person claims the request at the consent screen (a new agent has no binding
-- yet, so nobody knows whose it is until someone with a session says so).
CREATE TABLE IF NOT EXISTS pending_request (
  id             TEXT PRIMARY KEY,
  kind           TEXT NOT NULL,   -- person | auth
  agent_iss      TEXT NOT NULL,
  agent_sub      TEXT NOT NULL,
  person_id      TEXT,
  payload        TEXT NOT NULL,   -- JSON
  state          TEXT NOT NULL,   -- pending | interacting | approved | denied | expired | delivered
  code_hash      TEXT UNIQUE,     -- sha256(normalized interaction code); NULL once consumed
  result         TEXT,            -- JSON (the issued token) once approved
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  decided_at     INTEGER
);
CREATE INDEX IF NOT EXISTS pending_request_person ON pending_request(person_id, state);
CREATE INDEX IF NOT EXISTS pending_request_agent ON pending_request(agent_iss, agent_sub, state);

-- Missions. The blob is the exact bytes s256 was computed over.
CREATE TABLE IF NOT EXISTS mission (
  mission_s256        TEXT PRIMARY KEY,
  owner_iss           TEXT NOT NULL,
  owner_sub           TEXT NOT NULL,
  person_id           TEXT NOT NULL,
  blob                BLOB NOT NULL,
  approved_at         INTEGER NOT NULL,
  expires_at          INTEGER,
  state               TEXT NOT NULL CHECK (state IN ('active', 'terminated')),
  termination_reason  TEXT
);
CREATE TABLE IF NOT EXISTS mission_log (
  mission_s256  TEXT NOT NULL,
  seq           INTEGER NOT NULL,
  kind          TEXT NOT NULL,
  body          BLOB NOT NULL,
  s256          TEXT NOT NULL,
  at            INTEGER NOT NULL,
  PRIMARY KEY (mission_s256, seq)
);

-- Append-only audit, mirrored from the JSON audit stream so the dashboard can
-- answer "what did this agent do for me?".
CREATE TABLE IF NOT EXISTS audit (
  id       TEXT PRIMARY KEY,
  at       INTEGER NOT NULL,
  person_id TEXT,
  actor    TEXT NOT NULL,
  action   TEXT NOT NULL,
  subject  TEXT,
  detail   TEXT NOT NULL      -- JSON
);
CREATE INDEX IF NOT EXISTS audit_at ON audit(at);
CREATE INDEX IF NOT EXISTS audit_person ON audit(person_id, at);
