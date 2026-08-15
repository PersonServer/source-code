---
title: Hosted sandbox
description: A public, hosted AAuth Person Server for development — a live issuer that agents, Agent Providers and resources can build and test against without running psd yourself.
---

# Hosted sandbox

A public, hosted AAuth **Person Server**. Use it to build and test agents,
Agent Providers, and resources against a live person issuer **without
running psd yourself**.

```
https://sandbox.personserver.dev
```

It pairs with the hosted Agent Provider sandbox at
[sandbox.agentprovider.dev](https://agentprovider.dev/docs/sandbox.html):
that one says *what an agent is*; this one says *whose it is and what it may
do*. A full "agent acts for a person" flow can be exercised end to end
against the two.

> **Development and testing only.** Tokens issued by the sandbox have **no
> production value**. There is no SLA and no accounts in the ordinary sense.
>
> **Test people, test consents.** State persists (a Person Server that forgot
> what you allowed would be useless to test against), but it may be reset on
> a redeploy or a schema change. Do not build anything that depends on a
> sandbox person, binding, or grant persisting.

## At a glance

| | |
|---|---|
| Issuer / base URL | `https://sandbox.personserver.dev` (permanent) |
| People | Operator-issued — see [Getting a person](#getting-a-person) |
| Person token TTL | **900 s (15 minutes)** |
| Auth token TTL | **900 s (15 minutes)** |
| Signature window | 60 s — your clock must be correct |
| Signing algorithm | **Ed25519** — `alg: Ed25519`, not `EdDSA` |
| Missions | Enabled (default TTL 24 h) |
| Federation | Enabled (four-party) |
| Storage | SQLite on a persistent volume |
| Version | `psd` 0.1.0 |

## Quickstart

Check that it is up, and see exactly what a relying party sees:

```sh
# Is it up?
curl -s https://sandbox.personserver.dev/healthz

# The discovery document relying parties fetch (issuer + endpoints):
curl -s https://sandbox.personserver.dev/.well-known/aauth-person.json

# The public keys they verify person/auth tokens against:
curl -s https://sandbox.personserver.dev/.well-known/jwks.json

# Every machine endpoint requires a signature (expect 401 + Signature-Error):
curl -si -X POST https://sandbox.personserver.dev/person -d '{}' | head -5
```

## Getting a person

A Person Server represents real people, so people are not created by open
enrolment. To test against the sandbox you need a **test person** with a
passkey:

1. Ask for one — email `operator@personserver.dev` with the name to show on
   consent screens. You get back a single-use enrolment link (valid 15
   minutes).
2. Open the link in a browser that can create a passkey (a phone, a laptop
   with Touch ID / Windows Hello, or a security key). Create the passkey.
   That is your login for the sandbox — there are no passwords.
3. Point your agent at the sandbox as its Person Server. On the first
   request that needs your consent you are sent to the consent screen at
   `https://sandbox.personserver.dev`, sign in with the passkey, and decide.

Everything you allow, deny, or revoke is visible under your session; agents
you no longer trust can be cut off there.

## Public endpoints

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness. Returns the issuer. |
| `GET /.well-known/aauth-person.json` | Discovery — issuer, JWKS, token / mission / revocation endpoints. |
| `GET /.well-known/jwks.json` | Person Server public keys (OKP / Ed25519). |
| `POST /person` | Signed request from an agent → a person token (may defer to consent). |
| `GET /pending/{id}` | Poll a deferred request while the person decides. |
| `POST /token` | Signed request → an auth token for a resource. |
| `POST /revoke` | An Agent Provider revokes an agent's token. |
| `POST /mission`, `POST /mission/{s256}` | Propose, update, or complete a mission. |
| `/login`, `/enrol/…`, `/consent/…`, `/passkeys` | The human surface — HTML for the person's browser. |

Full semantics: the [HTTP API](api.md) reference.

## Rate limits

Enforced at the edge; exceeding a limit returns `429`.

| Path | Limit |
|---|---|
| `POST /person`, `/mission*` | 10 requests / minute / IP |
| `POST /token` | 30 requests / minute / IP |
| any path | 20 concurrent connections / IP; max body 64 KB |

## Building against it

**As an agent (or agent runtime):** use `https://sandbox.personserver.dev`
as the Person Server, and the [Agent Provider sandbox](https://agentprovider.dev/docs/sandbox.html)
for your identity. Expect the person-token request to defer the first
time — that is consent working. Handle `429` by backing off; handle the
15-minute token lifetime by refreshing.

**As a resource:** accept auth tokens with `iss = https://sandbox.personserver.dev`,
fetch the discovery document, follow `jwks_uri`, verify the Ed25519
signature and the request-signature binding. No pre-registration with the
sandbox is needed — trust bootstraps through HTTPS and discovery.

**As an Agent Provider:** the sandbox accepts revocations at `/revoke` and
participates in four-party federation; use it to test that your provider's
agents can be cut off from the person's side.

## The Ed25519 rule

The JWKS advertises `"alg": "Ed25519"`. Clients that still send or expect
`EdDSA` are rejected — that is the current AAuth wire form, not a bug.
