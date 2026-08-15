# RFC: `psd` — a self-hostable AAuth Person Server

| | |
|---|---|
| **Status** | Draft for discussion |
| **Binary** | `psd` |
| **Home** | `personserver.dev` (to be acquired) |
| **Protocol** | `draft-hardt-oauth-aauth-protocol-11` (14 Aug 2026) |
| **Relationship to this repo** | Moved here from the `apd` repository (`research/08-psd-implementation-rfc.md`), where it was authored as the seed document for `psd`. The protocol obligations it builds on are in [07 — Implementing a Person Server](https://agentprovider.dev/research/07-person-server.html). |

> This is the *implementation* RFC: what to build, in what order, with which
> trade-offs. The *protocol* obligations are in
> [07 — Implementing a Person Server](https://agentprovider.dev/research/07-person-server.html); this document does
> not restate them, it decides how to satisfy them.

---

## 1. Summary

`psd` is a self-hostable Person Server: a single Rust binary that lets a person
say **which agents may act for them, at which resources, and on what terms**.

It issues person tokens and auth tokens, holds the agent-person binding, runs
consent, and keeps the record. It is the counterpart to `apd`: `apd` says *what
an agent is*, `psd` says *whose it is and what it may do*.

## 2. Motivation

No good open Person Server exists. The role is the hardest in AAuth and the one
where the protocol is growing fastest — 64% of the `-11` change bullets landed on
it. Meanwhile a working AAuth deployment needs one the moment a resource wants
to know the human, which is most non-trivial cases.

`apd` proved the shape: a small Rust daemon, verifiable by anyone, deployable by
one engineer. `psd` should feel like that where it can, and be honest where it
cannot.

## 3. Design principles

1. **The person is the operator.** `psd` is something a person, family, or
   organisation runs for themselves. It is not a service that holds other
   people's identities on someone else's behalf.
2. **Self-hostable by one engineer.** One binary, one config file, one command.
   No message broker, no external queue, no cluster requirement.
3. **Verifiable, not trusted.** Everything `psd` asserts is a signed JWT anyone
   can check against a published JWKS. No shared secrets with any party.
4. **Minimal but honest dependencies.** `apd` is 8k lines with almost no deps.
   `psd` cannot be — it needs a UI, a database, and a way to reach a human. Add
   dependencies deliberately, and say why in this document.
5. **Fail closed, and fail loudly.** Every ambiguous authorization is a denial.
   Tamper evidence goes to operators, not just to a rejected response.

## 4. Non-goals

- **Not an identity provider.** `psd` authenticates the person by delegating —
  passkey, or OIDC to an IdP they already use. It stores no passwords.
- **Not a policy engine for resources.** Resources apply their own policy; a
  four-party deployment uses an Access Server. `psd` asserts identity and
  consent.
- **Not a mission control plane.** `mission_control_endpoint` serves principals
  AAuth does not define; the spec defers it to a companion document, and so do we.
- **Not multi-tenant SaaS in v1.** See §5.

## 5. Deployment shapes — decide this first

This single decision drives the data model, the auth model, and the UI. Three
shapes, in increasing cost:

| Shape | Persons | Authentication | Consent UI | Verdict |
|---|---|---|---|---|
| **A · Personal** | 1 | one passkey | one page, one device | **v1 target** |
| **B · Household / team** | 2–50 | passkeys, invite links | per-person dashboard | v2 |
| **C · Organisation** | many | OIDC federation to the company IdP, `tenant` claim | admin pre-authorisation, org policy | v3 |

**Recommendation: build A, design for C.** Shape A is genuinely useful, ships
fastest, and exercises every protocol path. But make `person_id` a first-class
column from day one rather than assuming a single row — retrofitting
multi-person into a single-person schema is the expensive mistake here.

## 6. Architecture

```
                     ┌──────────────────── psd ────────────────────┐
   Agent ───────────▶│  AAuth API (signed, machine)                │
   (agent token)     │    /person   /token   /revoke               │
                     │    /mission  /interaction                   │
                     ├─────────────────────────────────────────────┤
   Person ──────────▶│  Human UI (session, browser)                │
   (browser)         │    consent  ·  agents  ·  activity          │
                     ├─────────────────────────────────────────────┤
                     │  core: binding · directed sub · consent     │
                     │        policy · retention · audit           │
                     ├─────────────────────────────────────────────┤
                     │  store (SQLite / Postgres)   keys (Ed25519) │
                     └───────────────┬─────────────────────────────┘
                                     │
                          notify: push · email · webhook
```

**Two front doors, one core.** The machine API is AAuth-signed and stateless per
request. The human UI is session-based. They must not share an authorisation
path: a browser session must never be able to mint a token, and an agent token
must never grant UI access.

## 7. Technology decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | Rust | Matches `apd`; single static binary; `aauth-core` is Rust |
| Protocol primitives | **`aauth-core`** | Role-agnostic; do not reimplement JWTs or RFC 9421. See [the crate guide](https://github.com/AgentProvider/source-code/blob/main/crates/aauth-core/README.md) |
| HTTP | `hyper` + `http-body-util` | Same as `apd`; no framework needed for ~10 routes |
| Storage | **SQLite default, Postgres option** | *Departure from `apd`.* This data is relational and long-lived: bindings, consent, token records, audit. A KV store is the wrong shape. SQLite keeps single-binary self-hosting; Postgres covers shape C. |
| UI | **Server-rendered HTML, no SPA** | Consent screens must render in a hostile-network, JS-limited context and be auditable. A build step and a JS bundle are liabilities on a security surface. |
| Person auth | **Passkey (WebAuthn) first**, OIDC second | No passwords to store or leak. OIDC covers shape C. |
| Reaching the human | pluggable channel trait | Push, email, and webhook are deployment choices, not protocol |
| TLS | terminate in front | Same posture as `apd` |

**The dependency budget will be larger than `apd`'s. Say so.** WebAuthn, a SQL
driver, and a template engine are unavoidable. What stays out: no async ORM
magic, no SPA framework, no message broker.

## 8. Data model

The minimum that satisfies §7 and §13 of the protocol notes.

```sql
person(id, display_name, created_at)

-- The trust invariant: one agent, exactly one person. UNIQUE is the enforcement.
agent_binding(
  agent_iss, agent_sub,            -- PRIMARY KEY (iss, sub) — never sub alone
  person_id, status,               -- active | revoked
  platform, device,                -- agent-attested, display only
  bound_at, revoked_at
)

-- Directed identifiers. Derived, but stored so rotation is possible.
directed_sub(person_id, audience, sub, created_at)   -- UNIQUE(person_id, audience)

-- The retention obligation. Answers resource-token verification.
person_token_record(
  jti PRIMARY KEY, person_id, ps, sub, aud,
  mission_s256, tenant, exp, issued_at,
  purge_after                       -- exp + longest accepted resource-token life
)

consent(person_id, agent_iss, agent_sub, audience, scope, granted_at, expires_at, revoked_at)

pending_request(id, kind, agent_iss, agent_sub, payload, state, created_at, expires_at)

mission(mission_s256 PRIMARY KEY, owner_agent_iss, owner_agent_sub,
        blob, approved_resources, expires_at, state, termination_reason)
mission_log(mission_s256, seq, kind, body, digest, at)   -- updates are appended and digested

audit(id, at, actor, action, subject, detail)            -- append-only
```

Three notes that are easy to get wrong:

- `agent_binding` is keyed by **`(iss, sub)`**. A `sub` is unique only within its
  Agent Provider. The `UNIQUE` constraint on it *is* the one-agent-one-person
  invariant — enforce it in the schema, not in application code.
- `person_token_record.purge_after` makes retention a column, not a cron job.
  Forget early and you reject valid resource tokens; never forget and you grow
  without bound.
- `mission_log` is append-only and digested, because a mission's meaning is the
  approved blob **plus** its accepted updates, and an audit must read both.

## 9. Configuration

Mirror `apd`: one JSON file, environment overrides for secrets.

```json
{
  "issuer": "https://ps.example",
  "listen": "127.0.0.1:8430",
  "keys_file": "/var/lib/psd/psd-keys.json",
  "storage": { "backend": "sqlite", "path": "/var/lib/psd/psd.db" },

  "person_token_ttl_secs": 3600,
  "auth_token_ttl_secs": 3600,
  "signature_window_secs": 60,
  "resource_token_max_age_secs": 300,
  "retention_slack_secs": 3600,

  "directed_sub": { "mode": "pairwise" },

  "person_auth": { "method": "passkey" },

  "notify": { "channels": ["web"], "webhook_url": null },

  "missions": { "enabled": false },
  "federation": { "enabled": false },

  "metadata": { "name": "Example Person Server" },
  "telemetry": { "enabled": false, "endpoint": "http://localhost:4318" },
  "insecure_dev_mode": false
}
```

`issuer` is **permanent**, exactly as for `apd`: it lands in every `sub` you ever
derive and every token you sign. Decide the hostname before first run.

## 10. HTTP surface

**Machine (AAuth-signed):**

| Route | Phase | Notes |
|---|---|---|
| `GET /.well-known/aauth-person.json` | 1 | Metadata; `issuer` must equal the serving origin |
| `GET /.well-known/jwks.json` | 1 | Cacheable |
| `POST /person` | 3 | `person_token_endpoint` |
| `POST /token` | 4 | `auth_token_endpoint` |
| `GET /pending/{id}` | 4 | Deferred polling; honour `Prefer: wait=N` |
| `POST /revoke` | 5 | `revocation_endpoint`; **AP calls this** |
| `POST /mission`, `POST /mission/{s256}` | 6 | Owning agent's surface |
| `POST /interaction` | 6 | Relay to the human |
| `GET /healthz` | 1 | |

**Human (session):**

| Route | Purpose |
|---|---|
| `GET /` | Dashboard: agents, recent activity |
| `GET /consent/{pending_id}` | The decision screen |
| `POST /consent/{pending_id}` | Approve or deny |
| `GET /agents`, `POST /agents/{id}/revoke` | Connected-agents management |
| `GET /activity` | Audit view |

## 11. The consent screen is the product

Everything else is plumbing. This screen is where a human makes a decision they
will be held to, so it carries specific obligations:

- Show the **Agent Provider's** `name` and `logo_uri`, fetched from its metadata
  — not just the agent's self-description.
- Show the agent-attested `platform` and `device`, labelled as **unverified**.
- Show the resource's `name`, `description`, and `access_mode`, fetched from its
  metadata, so the person answers the question the resource will actually apply.
- On a **new** `(iss, sub)` tuple, say clearly that this is a new agent.
- Render `description` and `justification` as **sanitised** Markdown. They are
  attacker-controlled strings.
- For a person token, ask *"may this agent act at this resource as you?"* — not
  *"may it learn your name?"* Holding a person token is effectively access.

**[design]** Show the full resource token claims behind a disclosure toggle.
Experts want it; nobody else should have to see it.

## 12. CLI

```
psd serve      [--config psd.json]
psd keygen     [--keys psd-keys.json] [--rotate] [--prune-days N]
psd person add [--name "Alice"]          # shape A: run once
psd invite     [--ttl 3600]              # enrol a person (shape B/C)
psd agents     [list|revoke <iss> <sub>]
psd example-config > psd.json
psd version
```

`psd keygen` is deliberately identical in spirit to `apd keygen` — rotation is
online, old public keys stay in the JWKS until the longest token life has passed.

## 13. Security requirements

Beyond the protocol obligations in [07](07-person-server.md):

- **Constant-time mission lookup.** Absent and not-owned must be indistinguishable
  in status, body, headers, **and timing**, or the endpoint is an existence oracle.
- **Egress admission on every outbound fetch** (AP metadata, resource metadata,
  AS calls): HTTPS only, no redirects, no private addresses, size and time caps,
  pinned resolved IP. Reuse `apd`'s `httpc` module — it exists and is tested.
- **Separate the two front doors.** A browser session must never mint a token.
- **The pairwise secret is a signing key.** Losing it re-identifies every person
  at every resource. Store it with `keys_file`, back it up, never log it.
- **Rate-limit distinct `resource` values per agent** — each obliges a derived and
  retained directed `sub`.
- Append-only audit. Operators need to answer "what did this agent do for me?"

## 14. Milestones

| M | Deliverable | Proves |
|---|---|---|
| **M1** | Metadata, JWKS, keygen, agent-token + signature verification | A real agent can authenticate to us |
| **M2** | Person + passkey, agent-person binding, dashboard | We know who is who |
| **M3** | `POST /person` + retention + consent screen | **Identity-only resources work end to end** |
| **M4** | `POST /token` (three-party), pending + polling | Consent-gated resources work |
| **M5** | `POST /revoke` in and out | Real-time termination |
| **M6** | Missions | Governance |
| **M7** | AS federation, call chaining | Four-party |

**M3 is the release worth aiming at.** A resource that only needs to know *who
the person is* is fully served by a person token — no resource token, no auth
token. That is why `-11` added it, and it is the shortest path to something
useful.

## 15. Interop plan

Test against the live ecosystem rather than mocks:

- **Agent:** [`agentd`](https://agentd.dev)
- **Agent Provider:** `https://sandbox.agentprovider.dev` — open enrollment, real
  agent tokens, no sign-up
- **Resource:** [`mcpg`](https://mcpg.dev), `whoami.aauth.dev`

Failure paths to test explicitly: expired agent token; resource token naming a
`presented_jti` we never issued; `mission_s256` owned by a different agent
(**compare response timing**); an agent token presented after revocation.

## 16. Open questions

1. **Shape A or B for v1?** §5 recommends A. Confirm before schema work.
2. **SQLite or Postgres first?** SQLite for self-hosting; Postgres is a driver
   swap if the schema stays plain SQL.
3. **Passkey or OIDC first?** Passkey suits shape A; OIDC is mandatory for C.
4. **Missions in scope at all for v1?** They are 14 of 34 `-11` bullets and a
   large surface. Deferring to M6 is defensible.
5. **Does `psd` share `apd`'s `httpc`, `storage`, `audit`, `telemetry` modules?**
   They are proven and role-agnostic. Extracting them into a second shared crate
   (`aauth-server-util`?) would avoid a third copy — but only after `aauth-core`
   is published and stable.
