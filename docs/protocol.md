---
title: What a Person Server is
description: The AAuth Person Server role, distilled — the parties, the four tokens, the deferred consent flow, missions, federation, and what psd deliberately does not do.
---

# What a Person Server is

<span class="audience">ten minutes · no code</span>

AAuth is a protocol for letting AI agents act at services on someone's
behalf, with cryptographic proof at every hop. It splits the question *"may
this software do this here?"* into two questions answered by two different
parties:

- **Is this really agent X?** — answered by an **Agent Provider**. It issues
  the agent a short-lived, signed **agent token** (`aa-agent+jwt`) that is
  *bound to a key the agent holds*. Every request the agent makes is signed
  with that key; a copied token is useless without it.
  [agentprovider.dev](https://agentprovider.dev) runs one.
- **Does a person let agent X act for them, here, like this?** — answered by
  a **Person Server**. That is what psd is.

A **resource** (an API, an MCP server, a calendar) checks both answers by
verifying signatures against keys the two servers publish. It never has to
call either of them.

## What a Person Server does

A Person Server has four jobs, and psd does exactly these:

1. **Holds the binding.** Each agent identity (`iss` + `sub` from its agent
   token) is bound to *one* person — the first person who approves it. An
   agent cannot act for two people, and the binding is what the person revokes.
2. **Runs consent.** When an agent asks to act at a service the person has not
   yet allowed, the request is parked and the person is asked — on a screen
   that names the agent, the Agent Provider that vouches for it, the service,
   and the service's own description of what access means there.
3. **Issues two tokens, both short-lived and key-bound.**
   - A **person token** (`aa-person+jwt`) says *"this agent acts for this
     person at this service"*. The agent shows it to the service, which then
     decides for itself what the person may do there.
   - An **auth token** (`aa-auth+jwt`) says *"this person authorizes this
     specific access"* — scopes, an account, a mission — after the service
     asked for it explicitly with a **resource token** describing what it
     wants.
4. **Keeps the record and revokes.** Every issuance is retained until it can
   no longer be referenced; every decision is written to an audit log the
   person can read; revocation reaches the services that received tokens.

## The identifier a service sees

The `sub` in a person or auth token is **pairwise**: derived from the person
and the service with a secret only the Person Server holds. Two services
cannot compare their `sub` values and discover they serve the same person.
Within one service it is stable, so the service can keep an account for it.

## The deferred flow, end to end

```
 agent                          psd                              person
   |  POST /person {resource}     |                                 |
   |  (signed with the agent key) |                                 |
   |----------------------------->|  no consent on record           |
   |  202 Accepted                |                                 |
   |  AAuth-Requirement:          |                                 |
   |    interaction; url; code    |                                 |
   |  Location: /pending/{id}     |                                 |
   |<-----------------------------|                                 |
   |  (shows the person the url + code, or waits)                   |
   |                              |  opens url, logs in (passkey)   |
   |                              |<--------------------------------|
   |                              |  consent screen: agent, AP,     |
   |                              |  service, terms — Approve       |
   |                              |<--------------------------------|
   |  GET /pending/{id} (signed)  |  binds agent↔person, records    |
   |----------------------------->|  consent, mints the token       |
   |  200 {person_token}          |                                 |
   |<-----------------------------|                                 |
   |                                                                |
   |  ...later, to the service, signed, with the person token...    |
```

The interaction **code** is a short human-readable string; the person types
or confirms it so that a request they did not start cannot be approved by
accident. It is single-use and attempt-limited. Once consent for that
(agent, service) pair is on record, the next `POST /person` answers `200`
directly — no screen.

## Auth tokens: when a service wants more than "may act"

A person token is a statement about *presence*: this agent is here for this
person. Many services want a statement about *permission*: read the calendar,
but not delete it; act on account 42; only within this task. For that the
service issues the agent a short-lived **resource token** (`aa-resource+jwt`)
describing what it wants — the scope, the account, whether the person must be
asked afresh — and the agent brings it to `POST /token`.

psd verifies the resource token in the seven steps the draft prescribes
(including that it names a person token *psd itself issued* to *this agent*),
checks the person's consent for that scope — cumulative, so a subset of what
was already granted needs no new screen — and issues an **auth token** the
agent presents back to the service. The auth token names the person's
pairwise `sub`, the scope, the account, and the agent's key; it never names
the agent's identity or its Agent Provider.

## Missions

A **mission** is consent for a *task* rather than for a service: an agent
proposes a description, the tools it will use and the services it will touch;
the person approves it once, choosing a lifetime; psd returns a signed,
digested mission blob and a person token for each approved service. Every
token issued under the mission is capped by its expiry, the agent can append
progress updates the person reads on the dashboard, completion needs the
person's acceptance, and ending the mission revokes what was issued under it.

Missions are optional in the protocol; psd advertises `mission_endpoint`
only when `missions.enabled` is set.

## Federation and chaining (the four-party cases)

Some services do not evaluate authorization themselves; their resource token
names an **Access Server**. psd then obtains the person's consent *first* and
only afterwards federates to that server, forwards any interaction it demands
back to the agent, and hands the agent the Access Server's auth token once
verified. And a service that received an auth token may itself act as an agent
downstream, presenting that token as `upstream_token`; psd issues for the
person that token was issued for, and never binds the intermediary to anyone.

Both are implemented behind `federation.enabled` and tested against mock
servers. No live Access Server exists in the ecosystem yet, so treat these as
"ready to test" rather than "proven live".

## What psd deliberately does not do

- It does **not** issue agent tokens. That is the Agent Provider's job; psd
  verifies them by fetching the provider's published keys.
- It does **not** issue resource tokens. Services issue those.
- It does **not** see the person's data at any service. It says *who may
  act*; the service decides *what* and holds the content.
- It does **not** run a chat: the optional clarification, interaction relay,
  permission and audit endpoints and `mission_control_endpoint` are absent
  from its metadata, which is how a Person Server says it does not offer them.
- It does **not** accept a resource token that asks the *service* to interact
  with the person (`interaction` claim); that request is refused with
  `400 invalid_request`.

## Where the details live

- The specification: [draft-hardt-oauth-aauth-protocol](https://github.com/dickhardt/AAuth)
  (psd tracks `-11`) and `draft-hardt-httpbis-signature-key` (`-08`) for the
  `Signature-Key` header that carries the agent token on every request.
- The obligations of a Person Server, traced to the draft, and the design
  psd follows: [research/07](https://agentprovider.dev/research/07-person-server.html)
  and [research/08](https://agentprovider.dev/research/08-psd-implementation-rfc.html)
  on agentprovider.dev.
- The wire surface: [HTTP API](api.md). The guarantees: [Security model](security.md).
