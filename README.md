# psd — a self-hostable AAuth Person Server

`psd` is the Person Server role of [AAuth](https://github.com/dickhardt/AAuth):
a single Rust binary that lets a person say **which agents may act for them,
at which resources, and on what terms**. Where an Agent Provider vouches for a
piece of software ("this is agent X, here is its key"), `psd` vouches for the
human behind it: it issues **person tokens** (`aa-person+jwt` — "this agent
acts for this person at this resource") and **auth tokens** (`aa-auth+jwt` —
"this person authorizes this specific access"), holds the agent↔person
binding, runs consent, and keeps the record.

It is the counterpart to [`apd`](https://agentprovider.dev), the Agent
Provider, and builds on the same protocol library,
[`aauth-core`](https://github.com/AgentProvider/source-code/tree/main/crates/aauth-core).
Documentation: [personserver.dev](https://personserver.dev).

**Tracks:** `draft-hardt-oauth-aauth-protocol-11` (14 Aug 2026),
`draft-hardt-httpbis-signature-key-08`. AAuth is an IETF Internet-Draft, not a
released standard; wire formats change between revisions. Pin a commit.

## Status

All milestones **M1–M7** of the [implementation RFC](docs/rfc-psd-implementation.md)
(design decisions and their spec citations: [docs/DECISIONS.md](docs/DECISIONS.md)):

| | |
|---|---|
| ✅ `GET /.well-known/aauth-person.json`, `GET /.well-known/jwks.json`, `GET /healthz` | discovery, exact `accept_signature_algs`, keys with fully-specified `alg` |
| ✅ `psd keygen` — create, `--rotate`, `--prune-days N` | online rotation; old public keys stay in the JWKS until pruned; the pairwise secret lives with the signing keys |
| ✅ Inbound verification on every agent-facing endpoint | RFC 9421 (AAuth profile) · `scheme=jwt` only · agent token via JWKS discovery of the AP · `cnf.jwk` signed the request · `Content-Digest` recomputed over the body · single-level sub-agent rule · replay guard |
| ✅ Egress admission on every outbound fetch | HTTPS only, no redirects, no private/loopback, pinned IP, size + time caps |
| ✅ RFC 9457 problem details, `401` + `Signature-Error`, `403` never negotiates signatures | |
| ✅ Person + passkey (WebAuthn, pure Rust) | `psd person add` prints a one-time enrolment link; `/enrol/{token}` registers the first passkey; `/login` is a discoverable-credential ceremony; more passkeys from the dashboard |
| ✅ Relational store (SQLite) | `agent_binding` PRIMARY KEY `(iss, sub)` is the one-agent-one-person invariant; retention (`purge_after`), consent, pending, missions, audit tables ready |
| ✅ Dashboard | connected agents (agent-attested `platform`/`device` marked unverified) with revoke, activity, passkeys; session cookie + CSRF on every POST; strict CSP, no inline script |
| ✅ Templates | server-rendered `minijinja`, built-ins embedded, `ui.templates_dir` overrides by file name |
| ✅ `POST /person` — person tokens (`aa-person+jwt`) | consent on record → `200`; otherwise `202` + `AAuth-Requirement: requirement=interaction` + `Location: /pending/{id}`; `Prefer: wait=N` honoured; `subagent_token` (parent-mediated) supported; `exp = min(ttl, agent token exp)`; distinct-resource rate limit |
| ✅ `GET /pending/{id}` | signed and bound to the requesting agent; `200` once, then `410`; `403 denied` / `408 expired` |
| ✅ Consent screen | the question is "may this agent act at this service as you?"; AP name/logo, agent-attested platform/device (unverified), the resource's `name`/`description`/`access_mode` (fetched under egress admission, Markdown through a whitelist renderer, no clickable links); interaction code single-use + attempt-limited; the person's browser session records the decision; `psd pending approve|deny` for headless operators |
| ✅ Retention | every issued person token is retained (`jti, ps, sub, mission_s256, tenant, exp` + the agent) until `exp + resource_token_max_age + slack`, purged inline |
| ✅ `POST /token` — auth tokens (`aa-auth+jwt`, three-party) | resource token verified in all seven steps — `presented_jti` resolved against the retained record, a mismatch is **surfaced to operators** as `resource_token_mismatch`; consent per (agent, resource, scope), subset → `200`, superset or `prompt=consent` → `202`; auth token carries `ps`, mandatory `sub`, `cnf`, `scope`/`account`, no agent identifier, no `act` |
| ✅ `POST /revoke` — inbound | an Agent Provider revokes an agent token, signing as itself (`jwks_uri`); accepted only from the token's issuer; the token is denied from then on and the auth tokens issued for that agent are revoked at their resources |
| ✅ Outbound revocation | revoking a binding (dashboard or `psd agents revoke`) marks its auth tokens revoked and POSTs `{iss, jti}` to each resource's `revocation_endpoint`, signed as ourselves |
| ✅ Webhook channel | `notify.channels: ["web","webhook"]` POSTs a JSON notification (never the code) when a request is pending |
| ✅ Missions (`missions.enabled`) | `POST /mission` propose → consent screen (description, tools, resources, lifetime) → approved blob with `s256` over the exact stored bytes + a person token per approved resource; `action: update` appended to the digested log; `action: completion` accepted by the person; unknown and not-owned are one constant-time `404 mission_not_found`; `mission_s256` flows into person, resource and auth tokens, all capped by `expires_at`; end from the dashboard revokes tokens issued under it |
| ✅ AS federation (four-party, `federation.enabled`) | consent first, then a `jwks_uri`-signed POST to the AS's `auth_token_endpoint` with `resource_token` + `agent_token`; `requirement=claims` answered with the directed `sub`; `interaction`/`approval` forwarded to the agent, whose polls poll the AS; the AS's token verified (`iss`, `aud`, `cnf`, `sub`, `scope`) and recorded as provided. **Tested against a mock Access Server only** — no live AS exists yet |
| ✅ Call chaining (`upstream_token`) | a resource acting as an agent brings the auth token it received; we issue for *that* person (from a `sub` we issued), never binding the intermediary; consent asked and labelled as chained. **Tested with mock intermediaries only** |
| 🔜 resource-initiated interaction; clarification chat; interaction relay | an `interaction` claim in a resource token is refused with `400 invalid_request` |

`psd` does **not** issue agent tokens (that is the Agent Provider's job) or
resource tokens (the resource's).

Known limitations, stated rather than discovered: a resource token carrying an
`interaction` claim (resource-initiated interaction) is refused; a mission
update that materially expands the work is recorded and shown but not
re-consented; clarification chat, the interaction relay, permission/audit
endpoints and `mission_control_endpoint` are not offered (all OPTIONAL — their
absence from the metadata is the signal).

## Quick start

```sh
cargo build --release
./target/release/psd keygen --keys psd-keys.json      # signing key + pairwise secret, mode 0600
./target/release/psd example-config > psd.json        # edit issuer, keys_file, storage.path
./target/release/psd serve --config psd.json
./target/release/psd person add --name "Alice"        # prints a one-time link; open it to register a passkey
curl -s https://ps.example/.well-known/aauth-person.json
```

The person's browser must reach the issuer by its **hostname**: WebAuthn does
not allow passkeys on IP-address origins, so a development issuer is
`http://localhost:8430`, not `http://127.0.0.1:8430`.

`issuer` is **permanent**: it lands in every `sub` this server derives and in
`iss` of every token it signs. Decide the hostname before first run. Terminate
TLS in front of `psd`; the `Host` an agent signs (`@authority`) must equal the
issuer host.

For local development set `"insecure_dev_mode": true` and an `http://host:port`
issuer — that relaxes the identifier rules and admits loopback egress so a mock
Agent Provider on `127.0.0.1` works. Never enable it in production; `serve`
prints a warning when it is on.

## Configuration

One JSON file (`psd example-config`) plus environment overrides that win over
the file: `PSD_ISSUER`, `PSD_LISTEN`, `PSD_KEYS_FILE`, `PSD_DB_PATH`,
`PSD_TELEMETRY_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`.
Unknown fields are hard errors; every value is validated at load with a message
that says what to change. Backends that are planned but not yet built
(Postgres, OIDC person auth) are rejected rather than silently ignored. The
full reference is at [personserver.dev/docs/configuration](https://personserver.dev/docs/configuration.html).

Key knobs, with the protocol rule behind each:

| Key | Default | Why |
|---|---|---|
| `person_token_ttl_secs`, `auth_token_ttl_secs` | 3600 | tokens MUST NOT live longer than 1 h; issued `exp` is further capped by the agent token and any mission `expires_at` |
| `signature_window_secs` | 60 | `created` validity window |
| `resource_token_max_age_secs` | 300 | longest resource-token life accepted — and the retention floor for person-token records |
| `retention_slack_secs` | 3600 | records are kept `exp + max_age + slack` |
| `directed_sub.mode` | `pairwise` | `sub` per (person, resource) so resources cannot correlate |
| `limits.resources_per_agent_per_day` | 50 | each distinct `resource` obliges a derived, retained `sub` |
| `limits.code_attempts` | 5 | interaction-code brute-force bound |
| `ui.templates_dir` | unset | override the built-in HTML templates by file name |
| `missions.enabled` | false | advertise and serve `mission_endpoint`; `missions.default_ttl_secs` (24 h) is the lifetime pre-selected on the approval screen |
| `federation.enabled` | false | four-party: federate to a resource's Access Server after consent (mock-tested only) |
| `jwks_cross_origin_hosts` | `[]` | JWKS host must equal the issuer host unless listed |

## Layout

```
crates/psd/src/
  main.rs        CLI: serve · keygen · person add|list · invite · agents list|revoke · pending list|approve|deny · example-config · version
  config.rs      JSON + env, validated
  keys.rs        signing keys, rotation, JWKS, pairwise `sub` derivation
  metadata.rs    aauth-person.json
  reqctx.rs      inbound verification (the one path every agent request takes)
  jwks_cache.rs  issuer discovery: metadata → JWKS, floors and caps
  passkey.rs     WebAuthn RP ceremonies (webauthn_rp) + a test-only software authenticator
  store/         SQLite, plain SQL; schema.sql is the data model
  ui.rs          templates, sessions, CSRF, cookies, security headers
  httpc.rs       egress-hardened HTTP client (from apd)
  problem.rs     RFC 9457 + Signature-Error (from apd)
  audit.rs       structured audit lines (from apd)
  issue.rs · consent.rs · pending.rs · restoken.rs · revocation.rs · federation.rs · upstream.rs · notify.rs · markdown.rs
  router.rs · server.rs · app.rs · handlers/{wellknown,tokens,mission,ui}
  tests.rs       in-process tests with mock Agent Provider, resource and Access Server; RFC 9421/9530 vectors
templates/       built-in HTML (overridable via ui.templates_dir) · static/ css + passkey.js
docs/
  rfc-psd-implementation.md   the build plan this follows (internal)
  DECISIONS.md · STATUS.md    decision log and milestone status (internal)
  psd.example.json
  *.md                        the public documentation, published at https://personserver.dev/docs/
_config.yml · index.html · _layouts/ · _includes/ · assets/
                 the personserver.dev site (GitHub Pages, Jekyll)
```

`httpc.rs`, `problem.rs` and `audit.rs` are copied from
[`apd`](https://github.com/AgentProvider/source-code) (MIT OR Apache-2.0) —
it is a binary-only crate, so they cannot be imported. Each file says so in
its header; if they stay identical they will be extracted into a shared crate.

## Development

```sh
cargo test                                   # 110 tests, no network needed
cargo clippy --workspace --all-targets       # zero warnings is the bar
cargo fmt --all -- --check
```

Interop is tested against the live ecosystem: `https://sandbox.agentprovider.dev`
issues real agent tokens with open enrollment. The M3 check enrolls there,
signs a `POST /person` at a local `psd` (`202`), the operator approves with
`psd pending approve`, and the agent's `Prefer: wait` poll returns the person
token — with a replay, a wrong signing key, an `hwk` scheme, a body without
`Content-Digest` coverage, and a tampered agent token each refused with the
right `Signature-Error`. `apd`'s `tools/aauthcheck` conformance client can be
pointed at a running `psd` (`cargo run -- --target http://localhost:8430`).

CLI commands take `--config`; relative paths in the config (`storage.path`,
`keys_file`) resolve against the current directory, so run them from where you
run `psd serve`.

## License

MIT. Copied modules from `apd` are MIT OR Apache-2.0; see their headers.
