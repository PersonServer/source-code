# Decisions

Design and protocol-mapping decisions for `psd`, recorded so they survive
review conversations. Each entry names the draft text it rests on
(`draft-hardt-oauth-aauth-protocol-11` unless stated), the choice, and why.
Reversals are appended, not edited away.

Conventions: **D-n** = decision; ✅ agreed with the `apd` reviewer;
🟡 proposed, awaiting review; ↩ reversed.

## Architecture (from RFC §5, §7 — see `rfc-psd-implementation.md`)

- **D-1 ✅ Shape A (one person) for v1, designed for shape C.** `person_id` is a
  real column on every table from day one. Shape B/C add auth flows and UI, not
  schema.
- **D-2 ✅ SQLite first, plain SQL.** `rusqlite` with bundled SQLite; WAL; one
  connection behind a mutex. Postgres later behind the same `schema.sql`
  (TEXT ids, INTEGER seconds, BLOB opaque; no SQLite-only syntax outside
  PRAGMAs). `storage.backend = "postgres"` is *rejected* at config load until
  it exists.
- **D-3 ✅ Server-rendered HTML, no SPA.** `minijinja` (2 transitive deps),
  autoescape on, built-in templates embedded, `ui.templates_dir` overrides by
  file name (a broken override fails startup). No inline script or style
  anywhere; strict CSP. The consent screen needs no JavaScript.
- **D-4 ✅ Passkeys first; crate = `webauthn_rp`.** Pure Rust (p256,
  ed25519-dalek, rsa). `webauthn-rs` was rejected because it links OpenSSL,
  which breaks the single-static-binary deployment. Attestation is not
  verified (self-hosted; `attestation: none` semantics). RP ID = issuer host;
  IP-address issuers are refused with a message (WebAuthn forbids them).
- **D-5 ✅ `hyper` 1 + `http-body-util`, hand-rolled router.**
- **D-6 ✅ `aauth-core` as a git dependency pinned by `rev`**, not `branch`:
  draft revisions change the wire format and a `cargo update` must not change
  what `psd` accepts. Not published to crates.io without the human's sign-off.
- **D-7 ✅ Copy, don't import, `apd`'s `httpc.rs`, `problem.rs`, `audit.rs`.**
  `apd` is a binary-only crate. Each file carries an origin header; if they
  stay identical past M3, extract `aauth-server-util`.
- **D-8 ✅ Missions and AS federation are config-gated and rejected until
  built** (`missions.enabled`, `federation.enabled` → load error). Presence of
  `mission_endpoint` in metadata is how a PS advertises mission support, so
  an unimplemented endpoint must never be advertised.

## Inbound verification (§Verification, §Agent Token Verification, §Covered Components)

- **D-9 ✅ Every signature failure is `401` + `Signature-Error`; `403` never
  carries `Signature-Error` / `Accept-Signature-*`.** Enforced in
  `problem.rs` (`into_response` strips them from any 403).
- **D-10 ✅ Agent-token failures in `Signature-Key` are signature-layer 401s,
  not the token-endpoint 400s.** (Reviewer's check: `invalid_agent_token` /
  `expired_agent_token` appear only in the token-endpoint table with no
  trigger; this reading gives each error set exactly one job.) The agent token *is* the Signature-Key
  material, so a bad/expired one fails step 5 of §Verification →
  `401 Signature-Error: invalid_jwt` / `expired_jwt`. The token-endpoint codes
  `invalid_agent_token` / `expired_agent_token` (400) are used for an agent
  token carried in the *body* — `subagent_token`.
- **D-11 ✅ `Content-Digest` is recomputed over the received body; a mismatch
  is `401 invalid_signature`.** The signature binds only the header value; the
  comparison is the body-integrity half of the signature (that is why -11
  requires covering it on PS/AS bodies). Order: raw bytes → HTTP signature →
  digest → only then parse JSON. Accepts `sha-256` and `sha-512` members;
  every recognised member must match; at least one must be present.
- **D-12 ✅ `@authority` ≠ expected authority → `400 invalid_request` before
  any network fetch, no `Signature-Error`.** §Covered Components: `@authority`
  "binds the signature to the target host, preventing cross-host replay" — that
  only works if the verifier checks the authority is its own; reconstructing
  it from `Host` alone verifies a signature bound to *any* host. (Found and
  fixed in `apd` too, `4b21d91`.) The expected value is the issuer host with
  scheme-default ports normalized away, or `expected_authority` for a
  deployment behind a `Host`-rewriting proxy — the check is never simply off.
- **D-13 ✅ A signer whose agent token carries `parent_agent` →
  `400 invalid_request`** after verification. This is a MUST: §Single-Level
  Depth "A PS MUST reject a token request signed by an agent whose agent token
  has a `parent_agent` claim"; §Parent-Mediated Authorization "A sub-agent MUST
  NOT call the PS directly." The status code is unspecified; 400 because the
  signature is valid and it is not an authorization decision about a resource.
- **D-14 ✅ Replay guard keys on SHA-256(`jkt` ‖ signature bytes), not the
  draft's `(jkt, created, method, authority, path)` tuple.** (The tuple is a
  MAY, and contains no body component; the signature includes the body
  transitively via `content-digest`.) `created` is whole
  seconds and Ed25519 is deterministic, so two *distinct* legitimate requests
  in the same second collide on the tuple (concurrent token requests are
  explicitly allowed), while a real replay is byte-identical anyway. Applied
  only to body-carrying (state-changing) requests; a same-second GET poll is
  byte-identical to a replay, which is why the draft scopes the guard to
  state-changing requests. Detail text says "replayed".
- **D-15 ✅ Refresh-and-retry once on a JWT signature failure**, honouring the
  once-per-minute floor. If the refresh cannot happen (floor, network) the
  held key failed → `invalid_jwt`; if the refreshed JWKS lacks the `kid` →
  `unknown_key`.
- **D-16 ✅ `unsupported_scheme` responses carry `Accept-Signature-Scheme:
  jwt`;** `unsupported_algorithm` carries `Accept-Signature-Alg: Ed25519`.
- **D-65 🟡 A discovery fetch that fails is `503 temporarily_unavailable` +
  `Retry-After`, never `unknown_key`.** Found live: `sandbox.personserver.dev`
  answered `401 unknown_key` for a valid token whose `kid` was the only key
  in its Agent Provider's JWKS — because the metadata/JWKS fetch had failed
  (and the failed attempt then held the once-per-minute floor). The sig-key
  draft defines `unknown_key` as "does not match any key at the client's
  jwks_uri" and `cache_miss` as the `cached`-scheme identifier miss; neither
  describes "I could not ask". Reporting a fetch failure as `unknown_key`
  tells the agent its credential is wrong and sends its developer to
  re-enrol. So the cache distinguishes *the issuer answered* (kid absent →
  `unknown_key`; metadata/JWKS invalid → `issuer_*`/`invalid_key`) from *the
  issuer could not be consulted* (fetch failed, or the floor is held by a
  failed attempt): the latter is `503` with `error: temporarily_unavailable`,
  `Retry-After` = seconds until a fetch may be retried, no `Signature-Error`
  (nothing is known against the credential), and an audit event
  `discovery_unavailable` naming the issuer and the reason, so an operator
  sees an egress problem as one. Fits the draft's deferred-response state
  machine ("503 → back off per Retry-After, retry"). Under an active floor
  after a *successful* fetch, the fresh key set is authoritative: kid in it →
  used, kid absent → `unknown_key`. Applies to every discovery — agent
  tokens, resource tokens, upstream and Access Server tokens — because the
  reason is the same for all of them.

## Person token issuance (§Person Token Endpoint, §Person Token Structure)

- **D-17 ✅ Lifetime `exp = min(now + ttl, agent_token.exp, mission.expires_at)`**
  (the last term becomes live at M6). `person_token_ttl_secs` ≤ 3600 is
  enforced at config load.
- **D-18 ✅ Directed `sub` = base64url(HMAC-SHA256(pairwise_secret,
  len(person_id) ‖ person_id ‖ aud))**, derived on first sight and then
  **stored**; the stored row is authoritative and `UNIQUE(sub)` makes
  "unique within the issuer" a schema guarantee. Length-prefixed to remove the
  concatenation ambiguity of `person_id || aud`. Deterministic so a lost
  database with a surviving keys file reproduces the same values. The pairwise
  secret lives in the keys file, is never logged, and is treated as a signing
  key.
- **D-19 ✅ Retention is a column.** `person_token_record.purge_after = exp +
  resource_token_max_age_secs + retention_slack_secs`; rows past it are
  deleted inline on every insert (and are invisible to lookups). Correctness
  never depends on a cron job.
- **D-20 ✅ Retained record carries `agent_iss`/`agent_sub`** beyond the
  draft's minimum (`jti, ps, sub, mission_s256, tenant, exp`) — needed to
  revoke what was issued for an agent (§Token Revocation) and for the
  dashboard.
- **D-21 ✅ Binding is created lazily on the person's first approval**
  (§Agent-Person Binding). `agent_binding` PRIMARY KEY `(iss, sub)` is the
  invariant; an active binding to another person is refused, a revoked one may
  be re-bound. Same `sub` at a different AP is a different agent.
- **D-22 ✅ Consent is per (person, agent, resource, kind).** First person
  token for a resource prompts (§Person Token Exposure SHOULD); later requests
  with consent on record are answered `200` directly.
- **D-23 ✅ The consent question is "may this agent act at this resource as
  you?"** — the resource's `name`, `description`, `access_mode` are fetched
  (egress admission) and shown; AP `name`/`logo_uri` come from the cached
  metadata; agent-attested `platform`/`device` are shown and labelled
  unverified. Markdown (`description`, `justification`) is rendered through a
  whitelist renderer that never emits raw HTML and makes no attacker link
  clickable.
- **D-24 ✅ `mission_s256` while missions are disabled → `400 invalid_request`
  ("missions are not supported")**, and no `mission_endpoint` in metadata.
  When missions ship (M6) this becomes, verbatim from §Mission Endpoint
  Errors and §Mission Status Errors: unknown *or not-owned* →
  `404 mission_not_found` with identical status/body/headers/timing;
  the caller's own terminated mission → `403 mission_terminated` with
  `mission_status: "terminated"` and optional `termination_reason`. A test pins
  the current behaviour so the switch is deliberate.
- **D-25 ✅ Distinct-resource rate limit** (§Person Token Endpoint SHOULD):
  `limits.resources_per_agent_per_day` distinct `aud` values per agent per
  rolling day, counted from retained records; a resource the agent already
  holds a token for is never blocked. Exceeding → `429 too_many_requests`.
- **D-26 ✅ `upstream_token` (call chaining) → `400 invalid_request`** until
  M7 — the PS MUST verify it and cannot yet; fail closed rather than ignore a
  parameter that changes who the token is for.

## Deferred responses (§Deferred Responses, §Interaction Required, §Interaction Code Format)

- **D-27 ✅ `GET /pending/{id}` is a signed GET, bound to the agent** that
  created it (`(agent_iss, agent_sub)` on the row); another agent gets
  `404 not_found`. `Cache-Control: no-store` on the `200` carrying the token
  as well as on the `202`.
- **D-28 ✅ Interaction URL is `{issuer}/consent`** (no query, no fragment);
  the code is Crockford base32, 8 symbols (40 bits), shown as `XXXX-XXXX`,
  compared after stripping hyphens, folding case and `I/L→1`, `O→0`. The
  code is correlation only: the decision is recorded by the authenticated
  session. Single use; consumed on first successful presentation.
- **D-29 ✅ Approved results are delivered once** (`approved` → `delivered`);
  a later poll of a delivered request is `410`. Denied → `403 denied`;
  expired → `408 expired`.
- **D-30 ✅ `Prefer: wait=N` is honoured, capped at 50 s,** on the initial
  `POST /person` / `POST /token` and on polls. 50 s not 60: 60 s is the
  default idle timeout of many proxies and load balancers, and a hold on that
  boundary produces intermittent 502s (proxy read timeout should be ≥ 75 s).
  In-process decisions wake the waiter immediately; a decision by another
  process (the operator CLI) is seen by re-reading the row every 500 ms.
- **D-33 ✅ The operator can decide a pending request from the shell**
  (`psd pending list|approve|deny`). The operator holds the database and the
  keys, so this grants nothing a dashboard session could not; it exists for
  headless deployments and for shape A, where the operator is the person.
  Same code path as the consent screen (`consent.rs`); every audit record of a
  decision carries `via: "cli"` or `via: "consent"` so a shell decision and a
  passkey-authenticated one stay distinguishable. For shape B/C: the CLI must
  name the person (`--person`), and it should be gated or disabled in
  multi-person deployments — recorded now so it is not rediscovered.
- **D-34 ✅ Egress refuses RFC 2606/6761 reserved TLDs (`.example`,
  `.invalid`, `.test`) before DNS.** They never resolve legitimately; refusing
  early avoids a resolver round-trip an attacker (or a test) can induce.

## Auth tokens (§PS Token Endpoint, §Resource Token Verification, §Auth Token Structure)

- **D-35 ✅ Resource-token verification runs the seven steps in order, and
  step 6 resolves `presented_jti` against the retained record.** No record →
  `400 unknown_person_token`. A record → `ps`, `sub`, `mission_s256`, `tenant`
  must match exactly; beyond the listed four, the token's `iss` must equal
  the record's `aud` and the signing agent must be the record's agent. Any
  mismatch → `400 invalid_resource_token` **and** an audit event
  `resource_token_mismatch` (severity warning) naming the claims that differ,
  the token's values and the record's — surfaced to operators, not merely
  rejected. Errors are the token-endpoint 400s because the resource token is a
  body parameter, not the Signature-Key material.
- **D-36 ✅ A resource token whose `aud` is not this PS → `400
  invalid_request`** ("four-party federation is not supported by this build").
  The token may be perfectly valid for an Access Server; we simply cannot do
  the federation yet, so fail closed with a message that names the reason.
- **D-37 ✅ A resource token carrying an `interaction` claim
  (resource-initiated interaction) → `400 invalid_request`** ("resource-
  initiated interaction is not supported by this person server"). The
  extensibility posture argues for ignoring unknown claims; this one changes
  who drives the interaction, and ignoring it would run our consent while
  the resource waits at its own URL — rejecting is the safer half. Listed as
  a known limitation; revisit when a real resource hits it.
- **D-38 ✅ Consent for `scope` is per (person, agent, resource) and
  cumulative:** the union of unrevoked `auth` consents; a request whose
  scopes are a subset answers `200` directly; a superset, or `prompt=consent`,
  asks again. Approval grants all requested scopes (no partial grant in v1).
- **D-39 ↩ `prompt=none` with consent missing → `403 user_unreachable`**
  (was `denied`; reversed on review). `denied` means "user or approver
  explicitly denied" and the person was never asked — an agent might stop
  asking forever. `user_unreachable` is the terminal 403 about the user not
  being reachable, and `prompt=none` is the agent declining the only channel
  there is. The detail says to retry without `prompt=none`.
- **D-40 ✅ Auth token claims:** `iss` = `ps` = our issuer, `dwk
  aauth-person.json`, `aud` = resource, `sub` = the resource token's (proved
  equal to our record), `cnf.jwk` = the agent's (or sub-agent's) key,
  `scope`/`account`/`mission_s256`/`tenant` copied from the resource token,
  `exp = min(now + ttl, agent_token.exp, mission.expires_at)`. No agent
  identifier, no `act`, no delegation chain. Every issued auth token is
  recorded (`auth_token_record`) so it can be revoked at the resource.
- **D-41 ✅ A revoked binding denies auth tokens:** at `/token`, if the
  agent's binding is no longer active for the person the record names →
  `403 denied` ("the person has revoked this agent").
- **D-42 ✅ `justification` is capped at 8 KiB and rendered through the
  whitelist Markdown renderer** on the consent screen, labelled as written by
  the agent and unverified; it is also logged with the issuance.

- **D-76 ✅ The pre-11 resource-token claim name `person_token_jti` is
  accepted as `presented_jti`.** Found live: `whoami.aauth.dev`, the one
  third-party resource that issues resource tokens today, verifies a psd
  person token, then challenges `requirement=auth-token; resource-token=…`
  whose token carries `person_token_jti` — the name -11 renamed
  (§Document History: "Renamed the resource token claim person_token_jti
  to presented_jti … The value is unchanged"). Refusing it with
  `invalid_resource_token: missing presented_jti` (what `0.1.0` does)
  turns a rename into a broken flow for zero safety gain: same value, same
  step-6 resolution against the retained record, same mismatch checks.
  `presented_jti` is preferred when both are present. Second justification,
  found the same day: apd's published MCP-server guide had been showing the
  pre-11 resource-token shape (`agent`/`agent_jkt`, no `ps`/`sub`/
  `presented_jti`), so resources built from it would emit tokens no PS
  could resolve — the old name is not only whoami's.

## Revocation (§Token Revocation)

- **D-43 ✅ `POST /revoke` accepts only `scheme=jwks_uri`** (a server
  signing as itself; `Accept-Signature-Scheme: jwks_uri` on rejection), with
  the same authority, body-digest and replay rules as agent requests. Our own
  key is resolved locally, never by fetching our own metadata.
- **D-44 ✅ A revocation is accepted only from the issuer of the token being
  revoked** (`signer.id == body.iss`); anyone else → `403 forbidden` (no
  signature headers). No "trusted PS" list exists yet.
- **D-45 ✅ An Agent Provider's revocation of a `jti` we have never seen is
  still recorded (`200`).** This deviates from a literal reading of "`404` if
  the `(iss, jti)` pair is not recognized", and the literal reading is
  unsafe: an agent obtains a token, the AP revokes it at once, and only then
  does the agent present it here — a `404` would record nothing and the
  revocation would be silently lost. The AP is authoritative for its own
  tokens, so there is nothing to second-guess; the `404` is for a token the
  recipient *issued* and has no record of, where absence really is proof.
  For a foreign token, absence proves only that we have not seen it yet.
  (Verified live against a real `apd`, whose revocation POST it also fixed:
  it now covers the body digest.), so a later presentation of that token is denied;
  the record is kept for the agent-token maximum lifetime (24 h) plus slack.
  We can only answer `404` for our own tokens, where we know every `jti`.
- **D-46 ✅ A revoked agent token presented later → `401 Signature-Error:
  invalid_jwt`** ("revoked by its Agent Provider") — it is Signature-Key
  material that no longer verifies as a credential.
- **D-47 ✅ Inbound revocation triggers the outbound sweep:** the auth tokens
  we issued for the agent that token was seen from are marked revoked and each
  resource's `revocation_endpoint` is POSTed `{iss, jti}` signed as ourselves
  (`jwks_uri`, `aauth-person.json`, active `kid`, `content-digest` +
  `content-type` covered), under egress admission. A resource that advertises
  no `revocation_endpoint` cannot be told; the token expires within its
  lifetime — which is why lifetimes, not revocation, are the real control.
- **D-48 ✅ An AP revoking an agent token does *not* revoke the
  agent↔person binding.** Revocation is per token, `(iss, jti)`; the draft
  asks the PS to deny that token and revoke what it issued for that agent —
  not to destroy the binding. An AP may revoke one token routinely (rotation,
  a leak) while continuing to issue; if it distrusts the agent it stops
  issuing and the binding is moot. The event is attributed to the bound
  person and shows in their activity ("the agent provider revoked one of
  this agent's tokens; the binding is unchanged").
- **D-49 ✅ Revoking a binding (dashboard or CLI) also revokes its consents
  and sweeps its live auth tokens** at their resources.

## Missions (§Mission, §Mission Endpoint Errors, §Mission Status Errors)

- **D-50 ✅ `mission_endpoint` is advertised only when `missions.enabled`;**
  with it off, `POST /mission*` is `404 not_found` and `mission_s256` on any
  endpoint is `400 invalid_request` (pinned by test). With it on, D-24's
  split applies everywhere a `mission_s256` is named.
- **D-51 ✅ Unknown and not-owned are one answer, in constant time.**
  (Status/body/headers asserted strictly; timing is a smoke check — a strict
  timing assertion would be flaky in CI and end up deleted.)
  `lookup_owned` always runs the same query and compares SHA-256 digests of
  the owner tuple with `subtle::ConstantTimeEq` — against a fixed dummy when
  no row exists — then answers `404 mission_not_found` built the same way on
  both paths. A test asserts identical status/body/headers and that the
  medians of the two paths' lookup times are within 3×. Malformed `{s256}`
  and missing/unknown `action` are `400 invalid_request` decided *before* the
  lookup, revealing nothing. The owner's terminated mission is deliberately
  distinguishable: `403 mission_terminated` with `mission_status:
  "terminated"` and `termination_reason`.
- **D-52 ✅ The blob is canonical JSON of a fixed member set** —
  `approver`, `agent`, `approved_at` (ISO 8601 UTC), `expires_at` (when set),
  `description`, `approved_tools` (when non-empty), `approved_resources`
  (when non-empty) — serialized by serde_json (sorted keys, no whitespace),
  stored as those exact bytes, and `s256` = base64url(SHA-256(bytes)); the
  same bytes are returned base64url-encoded as `mission`.
- **D-53 ✅ The person chooses the lifetime at approval** (1 h / 1 d / 1 w /
  30 d / none — "none" is labelled least safe; default
  `missions.default_ttl_secs` = 24 h). Every token
  issued under the mission is capped by `expires_at`; every decision path
  compares `now` to it, and an active mission past it is recorded as
  terminated with reason `expired` on read.
- **D-54 ✅ Approval binds the agent (if needed), grants `person` consent
  for each approved resource for the mission's lifetime, and issues a person
  token for each,** returned in `person_tokens`; a resource that cannot be
  issued for (agent token expiring too soon) is omitted, and the agent may
  ask later.
- **D-55 ✅ (v1) Updates are accepted as recorded** (the PS MAY): appended to the
  log with the digest of the exact bytes stored, returned as `s256`; the blob,
  the mission's `s256` and every token are unchanged. The dashboard shows the
  approved description together with accepted updates so the person reads
  the accumulated picture. Person review of updates is not offered in v1.
- **D-56 ✅ Completion is proposed by the agent and accepted by the person:**
  `202` deferred; acceptance terminates the mission as `completed`
  (`200 {s256, termination_reason}` to the agent); "not yet" leaves it
  active (`403 denied` to the poll). Completion is not revocation: auth
  tokens issued under the mission expire on their own.
- **D-57 ✅ Ending a mission from the dashboard terminates it as `revoked`
  and revokes the auth tokens issued under it** at their resources.
- **D-58 ✅ Not built, deliberately:** clarification chat
  (`requirement=clarification`), the interaction relay endpoint,
  permission/audit endpoints, `mission_control_endpoint`. All OPTIONAL and no
  live party exercises them; `mission_control_endpoint` is deferred to a
  companion specification. Their absence from the metadata is the signal.

## AS federation and call chaining (§Access Server Federation, §Auth Token Delivery, §Call Chaining, §Upstream Token Verification)

- **D-59 ✅ Four-party is gated by `federation.enabled`** and exercised
  against a mock Access Server only — no live AS exists yet; the README says
  so. With it off, a foreign `aud` is refused (D-36).
- **D-60 ✅ Consent comes before federation.** The person's consent for
  (agent, resource, scope) is ours to obtain in every mode; the AS evaluates
  the resource's *policy*, not the person's willingness. Federating first
  would tell a third-party server that this person is considering this
  resource before they agreed to anything. So a four-party request runs the
  same consent path as three-party and, once consent is on record, calls the
  AS. When the AS then refuses, the dashboard says so plainly
  (`auth_token_denied` with `reason: access_server`), so the person does not
  see consent recorded and assume access works.
- **D-61 ✅ The PS-to-AS request is signed as ourselves** (`jwks_uri`,
  `aauth-person.json`, active `kid`) covering `content-type` +
  `content-digest`, POSTing `resource_token`, `agent_token` (REQUIRED even
  though the resource never sees an agent identifier — posture goes to the
  evaluator), and `subagent_token` / `upstream_token` when present.
- **D-62 ✅ The AS's deferred loop:** `202 requirement=claims` is answered by
  us (POST `{sub}` to `Location`, ≤ 5 rounds — the directed `sub` is the only
  identity claim we assert); `interaction` / `approval` / `clarification` are
  forwarded to the agent verbatim in our own `202` (our `Location`), and each
  of the agent's polls drives one signed poll of the AS's `Location`;
  `402` → `403 user_unreachable` (no billing relationship; the request
  cannot proceed); AS `403` → its error passed through; other 4xx passed
  through with the status; 5xx / malformed → `502 server_error`.
- **D-63 ✅ An AS-issued auth token is verified before delivery** per §Auth
  Token Delivery — signature via `aauth-access.json`, `iss` = the AS we
  called, `aud` = the resource, `cnf.jwk` = the agent's key, `sub` = the
  directed identifier we issued, `scope` ⊆ requested — and recorded as
  *provided* (`auth_token_record.iss` = AS) so revocation can reach the
  resource with the right `(iss, jti)`.
- **D-64 ✅ Call chaining issues for the upstream token's person, never for
  a binding.** `upstream_token` is verified per §Upstream Token Verification:
  an `aa-auth+jwt` we issued or provided (our record, not revoked), whose
  `aud` equals the requesting agent's `iss` (the intermediary is its own
  Agent Provider), whose `sub` we issued for exactly that audience. The
  intermediary acts for many people and is never bound to one; consent for
  (person, intermediary, downstream resource) is still asked, and the screen
  says the request is chained. Its mission, if any, comes from the upstream
  token (must be active) and may not be combined with `mission_s256`; its
  `tenant` is carried into the downstream token. Downstream scope is not
  constrained by upstream scope (§Why Downstream Scope Is Not Constrained).

## Human surface

- **D-31 ✅ Session cookie `HttpOnly; SameSite=Lax; Secure` (Secure omitted
  only for an http issuer in dev mode).** Lax, not Strict, because the person
  reaches the consent screen by a top-level navigation from another site — the
  interaction URL — and Strict drops the cookie on exactly that hop. Every
  state-changing UI POST requires the session's CSRF token (form field `csrf`
  or `X-CSRF` header).
- **D-32 ✅ Enrolment is a one-time link** printed by `psd person add` /
  `psd invite` (token stored hashed, ~15 min, single use); the first passkey is
  registered there. There are no passwords.

## Enterprise SSO — OIDC login for persons (`person_auth.method = "oidc"`)

Plan, written before the callback handler, for review. The premise: in psd
SSO authenticates a *human in a browser*; it never touches the agent
surface, and it never decides consent.

- **D-66 ✅ Config.** `person_auth.oidc = { issuer, client_id,
  client_secret_file, scopes (default ["openid","profile","email"]),
  required_claims (REQUIRED, non-empty), tenant_claim, display_name_claims
  (default ["name","preferred_username","email"]), provision (default
  true) }`. `client_secret_file` for the same reason `keys_file` is a file;
  read at startup into a redacted runtime struct, never into `Config`.
  Validation: block required when `method = "oidc"`, `https://` issuer
  (http only in dev mode), `openid` in scopes, secret file readable — and
  **`required_claims` must not be empty**: it is the authorization gate, and
  with JIT provisioning on by default an empty gate would give every
  account at the provider a person. Refused at startup, not warned about (a
  warning is read once, in a terminal, by someone busy, in exactly the
  configuration where it matters most — reviewer's point, applied in apd
  too). "Everyone in our domain" is written explicitly, `{"hd":
  "acme.com"}`. `redirect_uri` is fixed at `{issuer}/login/oidc/callback`
  and printed at startup so the operator can register it at the IdP.
- **D-67 ✅ `method: "oidc"` is additive: SSO is offered *in addition to*
  passkeys, per person.** Existing passkeys keep working, new ones can be
  added, enrolment links still work; the login page shows both buttons. An
  org can roll out SSO while an operator keeps a passkey for break-glass. If
  an operator wants passkeys off they cannot — this is documented loudly
  rather than made a switch, because the switch's failure mode is silently
  locking people out.
- **D-68 ✅ Discovery at startup, keys on the agent-token floor.**
  `{issuer}/.well-known/openid-configuration` is fetched once at startup
  through the same egress admission as everything else (a typo fails fast);
  its `issuer` must equal the configured one byte-for-byte (OIDC Discovery
  §4.3); `authorization_endpoint`, `token_endpoint`, `jwks_uri` are taken
  from it. `jwks_uri` must be same-origin with the issuer unless its host is
  in `jwks_cross_origin_hosts` (Google Workspace publishes its keys on
  `www.googleapis.com`; the operator lists it). ID-token keys are a separate
  small cache (RSA/ECDSA/EdDSA keys, `anyjwk` adapted from apd) refreshed on
  unknown `kid` under the same once-per-minute floor and 24 h cap; a fetch
  failure is a `503` login page, not a verdict (D-65).
- **D-69 ✅ Authorization Code + PKCE (S256), `state` and `nonce` bound to a
  single-use login row and a cookie.** `GET /login/oidc?next=` creates
  `oidc_login(id_hash, state_hash, nonce_hash, code_verifier, next,
  link_person_id, created_at, expires_at = +10 min, used_at)` and sets
  `psd_oidc=<id>` (`HttpOnly; SameSite=Lax; Secure; Path=/login/oidc;
  Max-Age=600`), then redirects to the IdP with `state`, `nonce`,
  `code_challenge`. On `GET /login/oidc/callback`: (1) the cookie names the
  row — unknown, used or expired → "start again"; the row is marked used
  *before* anything else and the cookie cleared, so a callback URL is
  spent on first presentation whatever happens next; (2) the `state` query
  parameter must equal the row's (hash compare, constant time) — an
  attacker who starts their own login and lures the victim to *their*
  callback URL fails here because the victim's cookie names a different
  row (or none), which is the login-CSRF / session-fixation case; (3) an
  `error` parameter is shown and audited; (4) the code is exchanged at
  `token_endpoint` with `code_verifier` and `client_secret_basic`, over
  egress admission; (5) the ID token is verified: `alg` in {RS256/384/512,
  ES256/384, EdDSA/Ed25519} (never `none`), `kid` → key, signature, `iss` ==
  configured, `aud` contains `client_id` (and `azp == client_id` when `aud`
  is plural), `exp`, `iat`, and **`nonce` equals the row's** (hash compare)
  — the row, not the cookie, is what binds `nonce`, so an ID token replayed
  into another login attempt cannot match; (6) `required_claims` are
  evaluated. Only then a session is created — the same session as a passkey
  login — and the browser is sent to the validated `next`.
- **D-70 ✅ The person is keyed on `(idp_iss, idp_sub)`, never email.**
  Table `person_identity(person_id, idp_iss, idp_sub, email, linked_at,
  last_login_at, UNIQUE(idp_iss, idp_sub))`. Email is mutable and
  reassignable — an offboarded `alice@` handed to a new Alice would inherit
  bindings and consents; the same reasoning as `(agent_iss, agent_sub)`,
  with a worse failure. On a successful login: known identity → that
  person; unknown identity with a `link_person_id` (a signed-in passkey
  person pressed "Connect SSO" on the sign-in-methods page) → linked to
  that person; unknown and `provision` on → a person is created just in
  time (display name from `display_name_claims`, first present); unknown
  and `provision` off → refused. An identity already linked to another
  person cannot be linked again. `email` is stored for display only.
- **D-71 ✅ `required_claims` uses apd's matcher, extended for arrays.**
  Claim path (dotted, longest-key-first lookup) → matcher: exact string,
  trailing-`*` prefix, or array of those (any-of). Because IdP `groups`
  claims are arrays, an array-valued *actual* claim satisfies the matcher
  when any element does — and an empty array never does, or a claim present
  but empty would satisfy a requirement. apd's matcher returned false for
  every array-valued claim (a `{"groups": "admins"}` rule could never
  match; it failed closed and silently); apd adopted these semantics
  (converged, with the empty-array rule pinned in both). Failure is a
  `403` page ("your account is not permitted to use this Person Server")
  and an audit event `oidc_login_denied {reason: "claims"}` — no person is
  created and nothing is linked.
- **D-72 ✅ Authentication is not consent.** Nothing in the SSO path
  touches `consent::approve`. The consent screen still renders and still
  requires the explicit `POST /consent/{id}` with the session's CSRF token;
  an IdP session shortens the walk to the button, never presses it. A test
  pins this: an SSO-authenticated `GET /consent/{id}` leaves the pending
  request pending.
- **D-73 ✅ `tenant`.** `tenant_claim` names an ID-token claim whose value is
  stored on the person (`person.tenant`, refreshed on each SSO login) and
  issued into every person token as `tenant` (§Person Token Structure: "the
  organization the person belongs to"; not part of the identifier). Retained
  in the person-token record, so step 6 of resource-token verification and
  the auth token carry it unchanged — which is where SSO pays off downstream:
  a resource applies org policy without knowing the IdP. Under call
  chaining the upstream token's `tenant` wins when present. Refresh, not
  pin, because org moves are rare and stale is worse; the consequence,
  stated in the docs: after a move, tokens minted before the next sign-in
  carry the old value until they expire (≤ 1 h), and a resource applying
  org policy sees the old tenant for that window.
- **D-74 ✅ Deprovisioning is deliberate: `psd person deactivate ID`.** The
  IdP deactivating a leaver stops logins; it does not touch bindings or
  consents, so their agents keep working until tokens expire. The command
  sets `person.status = deactivated`, revokes every active binding (with the
  consents and the outbound auth-token sweep the dashboard button does),
  ends active missions, deletes sessions, and refuses every future login —
  passkey or SSO — and every enrolment link; audited `person_deactivated
  {via: cli}`. `psd person activate ID` reverses the status (not the
  revocations). Re-checking at the IdP happens for free on every
  interactive SSO login (a refused or claim-failing login is a refused
  login). SCIM is not built; the limitation — that offboarding is a step
  the operator runs — is stated in the docs.
- **D-75 ✅ Audit and misc.** Logins are `signed_in {method: "passkey" |
  "oidc", idp_iss, idp_sub}` (the existing action, now with `method`) so an SSO login is distinguishable from a
  passkey one; provisioning is `person_provisioned {via: "oidc"}`. Logout is
  local (session deleted; no RP-initiated logout at the IdP). Startup prints
  `person_auth: passkeys + oidc (issuer, redirect_uri)`. `claims_supported`
  in metadata stays `["sub"]` (identity scopes beyond `sub` are not in this
  pass). Not built: SCIM, SAML, multi-tenant shape C, self-service
  deactivation.

## Vocabulary

- "Agent Provider" (never "Agent Server", the pre-`-01` name).
- `psd` issues person tokens and auth tokens **only**. Agent tokens are the
  Agent Provider's; resource tokens are the resource's.
