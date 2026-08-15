# Status

Milestone-by-milestone status of `psd`, kept in the repo because the
review channel between sessions is lossy. Decisions and their draft citations
are in [DECISIONS.md](DECISIONS.md); this file is the "what is built, how to
check it, what is open" companion.

Last updated: 2026-08-15. Build: 128 tests, `cargo clippy --workspace
--all-targets -- -D warnings` clean, `cargo fmt --check` clean. Pushed to
`github.com/PersonServer/source-code` (main); CI (fmt · clippy · test · helm
· docker) on every push, `edge` image + chart on main, `release` on `v*`
tags. Site: `personserver.dev` from this tree via GitHub Pages
(`_config.yml`, `index.html`, `docs/*.md`); needs the domain's A/AAAA
records pointed at GitHub Pages to resolve.

## Milestones

| M | State | Delivered |
|---|---|---|
| M1 | ✅ | metadata (`issuer`, `person_token_endpoint`, `auth_token_endpoint`, `revocation_endpoint`, `accept_signature_algs`, optional `mission_endpoint`), JWKS (every key with fully-specified `alg`), `psd keygen --rotate/--prune-days`, inbound verification (RFC 9421 AAuth profile, `scheme=jwt` only, agent token via JWKS discovery of any Agent Provider, `cnf.jwk` signed the request, `Content-Digest` recomputed, `@authority` = expected authority before any fetch, single-level sub-agent rule, replay guard keyed on the signature bytes, revoked-token check), egress admission (HTTPS only, no redirects, no private/loopback, pinned IP, size/time caps, reserved TLDs refused), RFC 9457 problem details |
| M2 | ✅ | persons + passkeys (`webauthn_rp`, pure Rust), one-time enrolment links (`psd person add`, `psd invite`), sessions (`HttpOnly; SameSite=Lax; Secure`) + CSRF on every UI POST, strict CSP with no inline script, `minijinja` templates embedded with `ui.templates_dir` override, dashboard (agents with revoke, consents, missions, activity, passkeys), SQLite store with the one-agent-one-person invariant as `PRIMARY KEY (iss, sub)` |
| M3 | ✅ | `POST /person`: consent on record → `200`; else pending + `202` `AAuth-Requirement: requirement=interaction; url; code` + `Location` + `Retry-After` + `Cache-Control: no-store`; `Prefer: wait=N` (≤ 50 s; CLI decisions seen within 500 ms); `subagent_token` (parent-mediated); distinct-resource limit (`429`); `GET /pending/{id}` signed + agent-bound (`202 pending/interacting`, `200` once then `410`, `403 denied`, `408 expired`); consent screen (AP name/logo, agent-attested platform/device marked unverified, resource `name`/`description`/`access_mode` fetched at request time, whitelist Markdown, new-agent banner, code single-use + attempt-limited); approval binds the agent, records consent, mints (`exp = min(now+ttl, agent_token.exp[, mission.expires_at])`), retains (`purge_after`), resolves the pending; `psd pending list|approve|deny` for headless operators (audited `via: "cli"`) |
| M4 | ✅ | `POST /token` (three-party): resource token verified in the seven steps of §Resource Token Verification; step 6 resolves `presented_jti` against the retained record — none → `400 unknown_person_token`; mismatch of `ps`/`sub`/`mission_s256`/`tenant` (plus `iss`≠record.aud, signer≠record.agent) → `400 invalid_resource_token` **and** audit `resource_token_mismatch` (severity warning) surfaced to operators; `agent_jkt` = signer/sub-agent key; `aud` must be us; lifetime ≤ `resource_token_max_age_secs`; consent per (person, agent, resource, scope), cumulative — subset `200`, superset or `prompt=consent` `202`, `prompt=none` without consent `403 denied`; auth token `iss = ps`, mandatory `sub`, `cnf`, `scope`/`account`/`mission_s256`/`tenant` copied, no agent id, no `act`; every auth token recorded; revoked binding → `403 denied`; `justification` (≤ 8 KiB) and `scope_descriptions` rendered through the whitelist renderer; webhook notify channel |
| M5 | ✅ | `POST /revoke` inbound: `scheme=jwks_uri` only (an AP signing as itself; our own key resolved locally), `{iss, jti}` both required, accepted only from the token's issuer (`403 forbidden` otherwise), recorded even for never-seen tokens (`200`), the token is denied from then on (`401 invalid_jwt`), auth tokens issued for that agent are revoked at their resources — signed by us as ourselves (`jwks_uri`, `aauth-person.json`, active `kid`, `content-digest`+`content-type` covered). Outbound sweep also on binding revocation (dashboard, `psd agents revoke`) and mission end |
| M6 | ✅ | missions (`missions.enabled`): `POST /mission` propose (`description`, `tools`, `resources`, metadata fetched per resource) → approval screen with lifetime choice → blob (canonical JSON, exact bytes stored, `s256`) + person token per approved resource; `POST /mission/{s256}` `action: update` (appended to the digested log) / `action: completion` (person accepts → `completed`); constant-time `404 mission_not_found` for unknown-or-not-owned (same query, `subtle` compare, identical response; timing test) and `403 mission_terminated` + `mission_status` + `termination_reason` for the owner's ended mission; `mission_s256` guarded on `/person` and at `/token` step 7; every token under a mission capped by `expires_at`; expiry checked on every decision path; End mission (dashboard) → `revoked` + revoke tokens issued under it |
| M7 | ✅ (mock-tested) | four-party (`federation.enabled`): consent first, then a `jwks_uri`-signed POST to the AS's `auth_token_endpoint` (`resource_token`, `agent_token`, `subagent_token?`, `upstream_token?`); `requirement=claims` answered with the directed `sub`; `interaction`/`approval` forwarded to the agent, whose polls poll the AS; `402` → `403 user_unreachable`; the AS's auth token verified per §Auth Token Delivery and recorded as provided (`iss` = AS). Call chaining: `upstream_token` verified per §Upstream Token Verification, person from a `sub` we issued, intermediary never bound, consent labelled chained, mission inherited from upstream, tenant carried. **No live Access Server exists; both are exercised against mocks only.** An `interaction` claim in a resource token is still refused |

Enterprise SSO (D-66…D-75, reviewed): OIDC person login, additive to
passkeys; `psd person deactivate` for offboarding; `tenant` in tokens.

Not built (all OPTIONAL, deliberately — see D-58): clarification chat,
interaction relay endpoint, permission/audit endpoints,
`mission_control_endpoint`, resource-initiated interaction, Postgres, OIDC
person auth.

## How to check it

```sh
cargo test                                          # 128 tests, no network
cargo clippy --workspace --all-targets -- -D warnings
```

Live, on this machine (dev config, `insecure_dev_mode`, issuer
`http://localhost:8430`, missions on):

```sh
# scratch dir: /tmp/claude-0/-root-personserver-source-code/30946919-12e6-4d28-8455-c3588ce6fbed/scratchpad/live
psd serve --config psd.json                        # (already running)
psd pending list --config psd.json                 # see waiting requests
psd pending approve <id> --config psd.json         # decide as Alice
# apd's conformance client (tools/aauthcheck), enrols a real agent at sandbox.agentprovider.dev:
cargo run -- --target http://localhost:8430 --poll  # 27/27 when approved mid-run
```

`POST /revoke` accepts an Agent Provider's `jwks_uri`-signed
`{"iss","jti"}` (see M5 above); to see the outbound sweep, have the agent
obtain a person token here first so its `(iss, jti)` is known.

## Open for review (🟡 in DECISIONS.md)

D-45 (unseen `jti` revocation recorded, `200`), D-60 (consent before
federation), and anything else marked 🟡. Reviewed and applied from the last
batch: D-36/37 ✅, D-39 ↩ `user_unreachable`, D-48 ✅ (+ dashboard
attribution), D-51/53/55/58 ✅.
