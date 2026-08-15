---
title: HTTP API
description: psd's HTTP surface — discovery, /person, /pending/{id}, /token, /revoke, /mission, the human UI routes, and the full error vocabulary.
---

# HTTP API

<span class="audience">reference</span>

psd has two front doors that never share a handler. The **machine surface**
(`/.well-known/*`, `/person`, `/pending/{id}`, `/token`, `/revoke`,
`/mission`, `/mission/{s256}`) is AAuth-signed and speaks JSON. The **human
surface** (`/`, `/login`, `/enrol/{token}`, `/consent`, `/activity`,
`/passkeys`, …) is session-authenticated HTML for the person's browser. This
page is the machine surface, plus a map of the human one at the end.

## Conventions

**Every agent-facing request is signed** per RFC 9421 with the AAuth
profile: the `Signature-Key` header carries the agent token with
`scheme=jwt`, the signature covers at least `@method @authority @path
signature-key`, and requests with a body also cover `content-type` and
`content-digest` (RFC 9530, `sha-256`). psd verifies, in this order: the
`@authority` equals the issuer host (before any network fetch); the
`Signature-Key` parses and the scheme is `jwt`; the agent token verifies
against its Agent Provider's published JWKS (discovered from
`aauth-agent.json`, cached with floors and caps) and is not expired or
revoked; the key in `cnf.jwk` signed the request within
`signature_window_secs`; the `Content-Digest` matches the body; a
body-carrying request is not a replay of a signature already seen; a
sub-agent's `parent_agent` is present only where allowed. Failing any of
these is `401` with a `Signature-Error` header naming the reason.

**`/revoke` is signed by a server, not an agent**: `scheme=jwks_uri`, the
signer's key resolved from its metadata document. An agent token there —
or a server key on an agent endpoint — is `401 unsupported_scheme` with an
`Accept-Signature-Scheme` header naming what is accepted.

**Errors are RFC 9457 problem details** (`application/problem+json`) with
`error` and `error_description`, plus `Signature-Error` on `401`. A `403`
never negotiates signatures. Bodies are limited to `max_body_bytes`.

**Deferred answers are `202 Accepted`.** When the person must decide, the
response carries:

```
HTTP/1.1 202 Accepted
AAuth-Requirement: requirement=interaction; url="https://ps.example/consent"; code="7XK4M2QP"
Location: https://ps.example/pending/p_…
Retry-After: 5
Cache-Control: no-store
Content-Type: application/json

{"status":"pending"}
```

The agent shows the person the `url` and `code` (or, when it can, opens the
URL with `?code=` for them), then polls `Location`. `Prefer: wait=N`
(RFC 7240) on the original request or on any poll holds the connection up to
`N` seconds (capped at 50) and answers as soon as the decision lands.

## Discovery

### `GET /.well-known/aauth-person.json`

The Person Server metadata document (cacheable, unsigned):

```json
{
  "issuer": "https://ps.example",
  "jwks_uri": "https://ps.example/.well-known/jwks.json",
  "person_token_endpoint": "https://ps.example/person",
  "auth_token_endpoint": "https://ps.example/token",
  "revocation_endpoint": "https://ps.example/revoke",
  "mission_endpoint": "https://ps.example/mission",
  "accept_signature_algs": ["Ed25519"],
  "scopes_supported": ["openid"],
  "claims_supported": ["sub"],
  "name": "Example Person Server",
  "description": "…", "logo_uri": "…", "documentation_uri": "…"
}
```

`mission_endpoint` appears only when `missions.enabled` is set: absence is
how a Person Server says it does not offer missions. Endpoints psd does not
offer at all (clarification, interaction relay, permission and audit
endpoints, `mission_control_endpoint`) are absent for the same reason.

### `GET /.well-known/jwks.json`

The public signing keys, every one with a fully-specified `alg`
(`Ed25519`) and a `kid`. Old keys stay published after rotation until pruned.

### `GET /healthz`

`{"status":"ok","issuer":"…","uptime_secs":n}`. Unsigned; for probes.

## `POST /person` — person tokens

*Agent-signed, JSON body.* Asks for a person token: "this agent acts for
this person at `resource`".

<dl class="fields" markdown="0">
<dt>resource</dt><dd>Required. The service's server identifier (<code>https://host</code>). Becomes the token's <code>aud</code>, and the audience the directed <code>sub</code> is derived for.</dd>
<dt>subagent_token</dt><dd>Optional. A sub-agent's agent token whose <code>parent_agent</code> is the signing agent, from the same Agent Provider. The token binds to the sub-agent's key; the binding and consent are the parent's.</dd>
<dt>mission_s256</dt><dd>Optional. Issue under an approved mission (the token carries <code>mission_s256</code> and is capped by the mission's expiry). Refused as unsupported when missions are off; <code>404 mission_not_found</code> for a digest that is not an active mission of this agent; <code>403 mission_terminated</code> for one that ended.</dd>
<dt>upstream_token</dt><dd>Optional (federation on). Call chaining: an auth token this server issued or brokered, presented by the resource that received it and now acts as an agent downstream. The person is the one that token names; the intermediary is never bound. Cannot be combined with <code>mission_s256</code>.</dd>
<dt>platform, device</dt><dd>Optional strings the agent says about itself; shown to the person marked <em>unverified</em>.</dd>
</dl>

**`200`** when consent for this (agent, resource) is on record:

```json
{"person_token":"eyJ…","expires_in":3542}
```

The token is `aa-person+jwt`: `iss` = this server, `aud` = the resource,
`sub` = the pairwise identifier for (person, resource), `cnf.jwk` = the
agent's (or sub-agent's) key, `exp ≤ min(now + person_token_ttl_secs,
agent_token.exp[, mission.expires_at])`, plus `mission_s256` and `tenant`
when they apply. Every issued token is retained (`jti`, `ps`, `sub`,
`mission_s256`, `tenant`, `exp`, the agent) for
`resource_token_max_age_secs + retention_slack_secs` past `exp`.

**`202`** with the deferred-answer headers above when the person must be
asked: a new agent, a resource this agent has no consent for, or an agent
whose binding was revoked. Poll `Location`.

**Errors**: `400 invalid_request` (missing or malformed fields, an
`interaction`-bearing sub-agent, chaining plus mission);
`400 invalid_agent_token` / `expired_agent_token` for a bad
`subagent_token`; `429 too_many_requests` with `Retry-After` when the agent
has asked for more distinct resources in a day than
`limits.resources_per_agent_per_day` (a resource it already holds a token
for is never counted); `401 …` for signature failures.

## `GET /pending/{id}` — poll a deferred request

*Agent-signed, no body.* Bound to the agent that made the original request:
anyone else gets `404 not_found`, so a leaked pending URL discloses nothing
(not even the person's directed `sub`). `Prefer: wait=N` holds up to 50 s.

| Status | Body | Meaning |
|---|---|---|
| `202` | `{"status":"pending"}` + `AAuth-Requirement` | Not decided; keep showing the person the URL and code. |
| `202` | `{"status":"interacting"}` | The person has arrived at the consent screen; stop prompting. |
| `200` | the token response of the original endpoint | Approved. Delivered **once**; the next poll is `410`. |
| `410 gone` | | Already delivered. |
| `403 denied` | | The person said no. |
| `408 expired` | | Nobody decided within `limits.pending_ttl_secs`. |

For federated requests (below) a `202` may instead carry the Access
Server's own `AAuth-Requirement`, forwarded; each poll drives one step with
that server.

## `POST /token` — auth tokens

*Agent-signed, JSON body.* Asks for an auth token: "this person authorizes
this specific access", after a resource asked for it with a resource token.

<dl class="fields" markdown="0">
<dt>resource_token</dt><dd>Required. The <code>aa-resource+jwt</code> the resource issued to the agent, verified in the seven steps below.</dd>
<dt>subagent_token</dt><dd>Optional, as on <code>/person</code>. The resource token's <code>agent_jkt</code> must then be the sub-agent's key.</dd>
<dt>upstream_token</dt><dd>Optional (federation on). Call chaining; the person it names must be the person the resource token's <code>presented_jti</code> record names.</dd>
<dt>prompt</dt><dd>Optional, space-separated: <code>none</code>, <code>login</code>, <code>consent</code>, <code>select_account</code>. <code>consent</code> forces the screen even when consent is on record; <code>none</code> forbids interaction and cannot be combined with the others.</dd>
<dt>justification</dt><dd>Optional Markdown (≤ 8 KiB) the agent gives the person for asking; rendered through a whitelist, marked as the agent's own words.</dd>
<dt>capabilities</dt><dd>Optional list of strings; recorded.</dd>
</dl>

**Resource-token verification**, every step a `400` when it fails:

1. It is a JWT of type `aa-resource+jwt` — `invalid_resource_token`.
2. Its signature verifies against the resource's published JWKS
   (`iss` = the resource, discovered from `aauth-resource.json`) —
   `invalid_resource_token`.
3. It is not expired (`expired_resource_token`), `iat` is not in the future,
   and `exp − iat ≤ resource_token_max_age_secs` — `invalid_resource_token`.
4. `aud` is this server; or, with federation on, an Access Server (four-party) —
   otherwise `invalid_request` saying federation is not enabled.
5. `agent_jkt` is the RFC 7638 thumbprint of the key that signed this request
   (or the sub-agent's) — `invalid_resource_token`. An `interaction` claim
   (resource-initiated interaction) is refused with `invalid_request`.
6. `presented_jti` names a person token this server retains —
   `unknown_person_token` if it names none (tampered, another server's, or
   past the retention window). Its `ps`, `sub`, `mission_s256` and `tenant`
   must equal the record's, and the record's agent must be the signer: a
   mismatch is `invalid_resource_token` **and** an audit event
   `resource_token_mismatch`, because it means the resource is confused or
   hostile.
7. Under a mission, the mission is still active for this agent
   (`404 mission_not_found` / `403 mission_terminated`).

Then consent: the resource token's `scope` (space-separated) is checked
against what the person has already granted this agent at this resource,
**cumulatively**. A subset
of the granted scopes → `200`; a superset, a first request, or
`prompt=consent` → `202` and the consent screen (which lists the requested
scopes with the resource's own `scope_descriptions`); `prompt=none` without
consent on record → `403 user_unreachable`. A revoked binding → `403 denied`.

**`200`**:

```json
{"auth_token":"eyJ…","expires_in":3599}
```

The token is `aa-auth+jwt`: `iss` = this server (or the Access Server, when
federated), `aud` = the resource, `sub` = the pairwise identifier, `cnf` =
the agent's key, `scope`, `account`, `mission_s256` and `tenant` as they
apply, `ps` = this server. It never names the agent's identity or Agent
Provider and carries no `act`. Every issued auth token is recorded so it can
be revoked and so it can serve as an `upstream_token` later.

**Four-party.** When the resource token's `aud` names an Access Server and
`federation.enabled` is set, psd first obtains the person's consent (or finds
it on record), then POSTs to the Access Server's `auth_token_endpoint`,
signed as itself with `scheme=jwks_uri`, carrying `resource_token`,
`agent_token` and any `subagent_token`/`upstream_token`. A `claims`
requirement is answered with the person's directed `sub`; an
`interaction`/`approval` requirement is forwarded to the agent as a `202`
whose polls poll the Access Server; a `402` becomes `403 user_unreachable`;
the Access Server's auth token is verified (`iss`, `aud`, `cnf`, `sub`,
`scope`) and recorded as provided. A refusal by the Access Server is
recorded as `auth_token_denied` with `reason: access_server`, so the person's
dashboard says it was the resource's policy.

## `POST /revoke` — an Agent Provider revokes an agent token

*Server-signed (`scheme=jwks_uri`), JSON body `{"iss":"…","jti":"…"}`.*
Accepted only from the issuer of the token being revoked (`403 forbidden`
otherwise). psd records the `(iss, jti)` as revoked — even one it has never
seen, answering `200`, because an Agent Provider may revoke a token before
the agent has presented it here and a `404` would lose the revocation — and
from then on refuses that token with `401 invalid_jwt`. If the token had
been seen, the auth tokens issued for that agent are revoked at their
resources. The binding itself is unchanged: revoking one agent token is not
the person revoking the agent.

```json
{"revoked":true}
```

Outbound, psd does the same to resources: when a person revokes an agent
(or ends a mission, or an Agent Provider's revocation reaches an agent with
live auth tokens), each resource that received an auth token gets a signed
`POST` to its `revocation_endpoint` with `{"iss": "<psd>", "jti": "…"}`.

## `POST /mission` — propose a mission

*Agent-signed, JSON body; `404 not_found` unless `missions.enabled`.*

<dl class="fields" markdown="0">
<dt>description</dt><dd>Required Markdown: what the agent proposes to do.</dd>
<dt>tools</dt><dd>Optional list of <code>{name, description}</code> the agent says it will use. Shown as declared and unenforced.</dd>
<dt>resources</dt><dd>Optional list of server identifiers the mission will touch. Each resource's metadata is fetched (under egress admission) so the person sees its name, description and access mode.</dd>
</dl>

Always **`202`** — a mission is a decision — then, once approved, the poll
returns:

```json
{
  "s256": "…",
  "mission": "<base64url of the canonical mission JSON>",
  "person_tokens": { "https://calendar.example": "eyJ…", "https://mail.example": "eyJ…" }
}
```

`s256` is the SHA-256 (base64url) of the exact stored blob bytes; it is the
mission's identifier everywhere (`mission_s256` in person, resource and auth
tokens). `person_tokens` holds one token per approved resource, capped by
the lifetime the person chose. `403 denied` if the person declined.

## `POST /mission/{s256}` — update or complete a mission

*Agent-signed, JSON body with `action`.*

- `{"action":"update","description":"…"}` — appended to the mission's log,
  which the person reads on the dashboard. **`200`**
  `{"s256":"<digest of the log entry>"}`. Nothing is re-consented; the blob
  and every token are unchanged.
- `{"action":"completion","summary":"…"}` — asks the person to accept that
  the mission is done. **`202`**; the poll returns
  `{"s256":"…","termination_reason":"completed"}` on acceptance
  (the mission is then ended and its tokens revoked) or `403 denied` if the
  person said *not yet*.

For a digest that is not an active mission **of this agent** — unknown, or
another agent's — the answer is one constant-time `404 mission_not_found`
that reveals nothing. For this agent's ended mission it is
`403 mission_terminated` with `mission_status: "terminated"` and
`termination_reason` (`completed`, `revoked`, `expired`). A malformed digest or an unknown
`action` is `400 invalid_request` before any lookup.

## Error vocabulary

| Status | `error` | Where |
|---|---|---|
| 401 | `invalid_signature`, `invalid_input` (+ `required_input`), `invalid_key`, `unknown_key`, `invalid_jwt`, `expired_jwt`, `issuer_missing`, `issuer_mismatch`, `unsupported_scheme` (+ `Accept-Signature-Scheme`), `unsupported_algorithm` (+ `Accept-Signature-Alg`), `cache_miss`, `invalid_request` | request signature / agent token; always with `Signature-Error` |
| 400 | `invalid_request` | malformed body, unsupported parameter, disabled feature named, resource-initiated interaction |
| 400 | `invalid_agent_token`, `expired_agent_token` | `subagent_token` |
| 400 | `invalid_resource_token`, `expired_resource_token`, `unknown_person_token` | `/token` resource-token verification |
| 403 | `denied` | the person declined, or the binding is revoked |
| 403 | `user_unreachable` | `prompt=none` with nothing on record; an Access Server answered `402` |
| 403 | `forbidden` | `/revoke` from someone other than the token's issuer |
| 403 | `mission_terminated` (+ `mission_status`, `termination_reason`) | this agent's ended mission |
| 404 | `mission_not_found` | unknown or not this agent's mission (constant time) |
| 404 | `not_found` | no route; a pending request that is not this agent's; missions disabled |
| 408 | `expired` | pending request timed out |
| 410 | `gone` | pending result already delivered |
| 429 | `too_many_requests` (+ `Retry-After`) | distinct-resource limit |
| 500 | `server_error` | |

## The human surface

Session-authenticated HTML; every POST carries a CSRF token; strict CSP
with no inline script; the session cookie is `HttpOnly; SameSite=Lax;
Secure`. Not an API — listed so an operator knows what to expose (all of it,
at the issuer origin) and what to leave alone.

| Route | Purpose |
|---|---|
| `GET /` | dashboard: pending decisions, agents (revoke), missions (end), consents, activity |
| `GET /login`, `POST /login/options`, `POST /login/finish`, `POST /logout` | passkey sign-in (discoverable credential) |
| `GET /enrol/{token}`, `POST /enrol/{token}/options`, `POST /enrol/{token}/finish` | one-time enrolment: register the first passkey |
| `GET /consent?code=…`, `GET /consent/{id}`, `POST /consent/{id}` | find a pending request by code; the consent screen; the decision |
| `POST /agents/revoke`, `POST /missions/end` | revoke a binding; end a mission |
| `GET /activity` | the full audit record for this person |
| `GET /passkeys`, `GET /passkeys/add`, `POST /passkeys/options`, `POST /passkeys/finish` | list and add passkeys |
| `GET /static/…` | psd's own CSS and the small WebAuthn script |
