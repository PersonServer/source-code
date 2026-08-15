---
title: Security model
description: What psd verifies, what it stores, what it refuses, and the guarantees it does not make — for operators deciding whether to run it and reviewers deciding whether to trust it.
---

# Security model

<span class="audience">for operators · reviewers</span>

A Person Server is where a human's authority enters an agent system, so
the useful question is not "is it secure" but *what exactly does it check,
what does it hold, and what happens when each of those is attacked*. This
page answers that for psd, in the order an attacker would meet it.

## Inbound: what a request must prove

Every agent-facing endpoint runs the same verification, in a fixed order,
and nothing else runs until it passes:

1. **The request was addressed to us.** The signed `@authority` must equal
   the issuer host (or `expected_authority`) *before any network fetch*. A
   signature valid for another host is refused as such; a request cannot be
   replayed against a different Person Server, and an attacker cannot make
   psd fetch metadata by naming a foreign host.
2. **The agent token is real.** `Signature-Key` must be `scheme=jwt` and
   the token an `aa-agent+jwt` whose signature verifies against the JWKS
   its issuer publishes — discovered from `/.well-known/aauth-agent.json`
   at the issuer's own origin (cross-origin `jwks_uri` only for hosts you
   list), fetched under the egress rules below, cached with a 60-second
   refetch floor and a 24-hour cap so a flood of unknown `kid`s cannot make
   psd hammer a provider. Expiry, `iat`, and the issuer's identity are
   checked, and the token's `(iss, jti)` must not be on the revocation list.
3. **The agent holds the key.** The signature over the request must verify
   with the key in the token's `cnf.jwk`, and `created` must be within
   `signature_window_secs`. Possession of a token without its private key
   proves nothing.
4. **The body is the body.** `Content-Digest` (SHA-256) is recomputed and
   compared; body-carrying requests must cover it in the signature.
5. **It is not a replay.** Body-carrying requests are checked against a
   cache keyed on the signature bytes for the length of the window; the
   same signed request twice is `401`.
6. **Sub-agents are one level deep.** A token with `parent_agent` may sign
   only where the draft allows it (as `subagent_token`, mediated by its
   parent), never directly.

Server-to-server requests (`/revoke`, and psd's own outbound calls to
resources and Access Servers) use `scheme=jwks_uri` — the signer's key
resolved from its own metadata — and are refused on agent endpoints, and
vice versa, with an `Accept-Signature-Scheme` header saying which is
accepted.

## Outbound: what psd will fetch

psd fetches metadata and keys from URLs an attacker chose (an agent token
names its issuer; a resource token names its resource; a mission names
resources). Every outbound request goes through one client with these
rules, none of which can be turned off outside `insecure_dev_mode`:

- **HTTPS only**; certificates verified against the Mozilla root store.
- **No redirects followed**, ever.
- **No private, loopback or link-local destinations.** A hostname is
  resolved first; if *any* address is private the fetch is refused; the
  admitted addresses are pinned for the connection (no DNS rebinding) and
  tried in turn (dual-stack hosts work).
- **Reserved TLDs** (`.example`, `.invalid`, `.test`, `.localhost`) are
  refused before DNS.
- **Size and time caps** on every response.

## What the person's decision rests on

The consent screen is built from what psd verified and labels what it did
not:

- The agent identifier and its Agent Provider are **verified** (steps 2–3
  above); the provider's display name and logo come from its metadata.
- `platform` and `device` are **agent-supplied and marked unverified**.
- The resource's name, description, access mode and scope descriptions come
  from *its* metadata, fetched at request time under the egress rules, and
  rendered through a **whitelist Markdown renderer**: no raw HTML, links
  shown as text (a consent screen must not be a phishing page), input
  capped at 8 KiB. The agent's `justification` and a mission's text go
  through the same renderer and are marked as the agent's own words.
- The interaction **code** only locates the pending request. It is
  Crockford base32, single-use, and terminally failed after
  `limits.code_attempts` wrong guesses. Nothing is decided by presenting a
  code: the decision is made by an authenticated browser session (passkey
  login, `HttpOnly; SameSite=Lax; Secure` cookie, CSRF token on every POST,
  strict CSP with no inline script) or by the operator's CLI, and the audit
  record says which.
- A **new agent** — never bound to anyone — is announced with a banner.

The agent's poll of the result is itself signed and bound to the agent
that made the request; a leaked `/pending/{id}` URL yields `404` to anyone
else and would in any case yield a token unusable without the agent's key.

## What a token says, and what it cannot be used for

- Person and auth tokens are **Ed25519-signed, key-bound (`cnf`) and
  short-lived** (≤ 1 hour, further capped by the agent token's expiry and
  any mission's). A stolen token cannot be used without the agent's private
  key and stops working within the hour regardless.
- The **`sub` is pairwise**: HMAC-SHA256 over the person and the audience
  with a secret only psd holds. Two resources cannot correlate a person by
  comparing identifiers; within one resource the identifier is stable.
- Auth tokens **do not name the agent** or its provider — the resource
  learns that *this person* authorized *this access* for *this key*, and
  no more.
- **One agent, one person.** The binding table's primary key is the agent
  identity; the schema, not a check, enforces that an agent cannot act for
  two people. A binding revoked by the person stays revoked until the
  person approves the agent again.

## What psd stores, and for how long

| Data | Why | How long |
|---|---|---|
| Persons and passkey **public** keys | login | until deleted by the operator |
| Agent bindings and consents | the record of who allowed what | until revoked; revoked rows are kept as history |
| Directed identifiers | so a `sub` in a resource token can be resolved to the person | as long as the person |
| Person-token records (`jti`, `ps`, `sub`, `mission_s256`, `tenant`, `exp`, agent) | step 6 of resource-token verification | `exp + resource_token_max_age + slack`, then purged |
| Auth-token records | revocation and call chaining | until expiry plus slack |
| Seen and revoked agent tokens | revocation | bounded by the agent-token maximum lifetime |
| Pending requests, missions and their logs | the flow itself; the person's review | pending: until decided or expired; missions: as history |
| Audit events | the person's *Activity* and the operator's log | as long as the database |
| Sessions, enrolment links, interaction codes | | short, single-use where applicable |

psd never stores a token it did not issue, never stores a passkey private
key (it never sees one), and never sees anything a resource holds. The
database is personal data; the [operator guide](install.md#backups) says how
to keep it.

## Revocation

- A **person revoking an agent** (dashboard or CLI) marks the binding
  revoked, revokes its consents, marks its live auth tokens revoked, and
  POSTs a signed revocation to every resource that received one — signed by
  psd as itself. Ending a mission does the same for tokens issued under it.
- An **Agent Provider revoking an agent token** (`POST /revoke`) is accepted
  only from the token's issuer, is recorded even for a token psd has never
  seen (so a revocation cannot be lost to a race with the agent's first
  request), and triggers the same sweep of auth tokens for that agent.
- Everything is short-lived, so even a resource that never learns of a
  revocation stops accepting the token within the hour.

## Signals worth watching

Two audit events mean something is wrong outside psd:

- `resource_token_mismatch` — a resource presented a resource token whose
  `presented_jti` names a person token psd issued, but for a different
  agent, person, mission or tenant. The resource is confused or hostile.
- `person_token_denied` with `reason: too_many_resources` — one agent asked
  for more distinct resources in a day than allowed; a probe, or a
  misconfigured agent.

Also: `revocation_refused` (someone other than a token's issuer tried to
revoke it), and repeated `401`s from one Agent Provider (its metadata may
have moved).

## What psd does not guarantee

- **It does not verify what an agent claims about itself** beyond its
  identity — `platform`, `device`, a mission's tool list, its
  justification. It shows them, labelled.
- **It cannot stop a resource from doing what it likes** with a token it
  legitimately received. The auth token says what the person authorized;
  the resource decides what to enforce.
- **It cannot recall a token already issued** — only refuse the next one
  and tell resources. Lifetimes are the real bound.
- **A mission update that materially expands the work is recorded and
  shown, not re-consented.** The person can end the mission from the
  dashboard.
- **Federation and chaining are tested against mock servers only.** No live
  Access Server exists yet.
- **It runs as one instance on one SQLite file.** Availability is yours to
  arrange; correctness does not depend on being always up (agents retry,
  pending requests wait).
- **The keys file is a single secret.** Whoever holds it can sign as your
  server and derive every directed identifier. It is the thing to protect.
