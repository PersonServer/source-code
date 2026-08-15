---
title: Documentation
description: Documentation for psd, a self-hostable AAuth Person Server — for the people who use one and the operators who run one.
---

# Documentation

**psd** is a self-hostable [AAuth](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)
**Person Server**: the part of the protocol that speaks for the human. Where an
Agent Provider vouches for a piece of software ("this is agent X, here is its
key"), a Person Server vouches for the person behind it ("agent X acts for
this person at this service, and here is what they allow"). psd holds the
agent ↔ person binding, runs consent, issues **person tokens** and **auth
tokens**, keeps the record, and revokes.

New to the idea? Start with [What a Person Server is](protocol.md) — ten
minutes, no code.

## Try it first

A public **[hosted sandbox](sandbox.md)** runs at `https://sandbox.personserver.dev` —
a live Person Server to build agents, providers and resources against, without
running psd yourself. Test people are issued on request; tokens have no
production value.

## Pick your door

<div class="doors" markdown="0">
  <a class="door" href="for-people.html">
    <span class="k">for people</span>
    <h3>Using your Person Server</h3>
    <p>You have been given an enrolment link, or an agent just sent you to a consent screen. What is being asked, what approving means, and how to take it back.</p>
    <span class="go">Read the guide →</span>
  </a>
  <a class="door" href="install.html">
    <span class="k">for operators</span>
    <h3>Install &amp; deploy</h3>
    <p>You are going to run the binary — for yourself, your family, or your organisation. Building, the permanent issuer, TLS, the first person, day-two operations.</p>
    <span class="go">Read the guide →</span>
  </a>
</div>

## Reference

| Page | What it covers |
|---|---|
| [Configuration](configuration.md) | Every field of `psd.json`, its default, and the protocol rule behind it; environment overrides |
| [Command line](cli.md) | `serve`, `keygen`, `person`, `invite`, `agents`, `pending`, `example-config` |
| [HTTP API](api.md) | Discovery documents, `/person`, `/pending/{id}`, `/token`, `/revoke`, `/mission`, the error vocabulary |
| [Templates & branding](templates.md) | Overriding the built-in HTML by file name; the variables each template receives |
| [Security model](security.md) | What psd verifies, what it stores, what it refuses, and the guarantees it does not make |

## The ecosystem

- **[agentprovider.dev](https://agentprovider.dev)** — `apd`, the AAuth
  Agent Provider that issues the agent identities psd verifies. It runs a
  public sandbox with open enrollment, which is the easiest way to get a real
  agent token to test psd with; psd runs the matching
  [Person Server sandbox](sandbox.md). psd builds on the same protocol library,
  [`aauth-core`](https://github.com/AgentProvider/source-code/tree/main/crates/aauth-core).
- **[agentd.dev](https://agentd.dev)** — a minimal, MCP-native agent
  runtime that enrols with an Agent Provider, holds its own key and signs
  every request: the kind of agent that appears on psd's consent screen.
- **[mcpg.dev](https://mcpg.dev)** — a governed MCP endpoint that verifies
  the per-request agent signature in front of your MCP servers: the kind of
  resource psd's tokens are presented to.
- **[The AAuth drafts](https://github.com/dickhardt/AAuth)** — psd tracks
  `draft-hardt-oauth-aauth-protocol-11` and `draft-hardt-httpbis-signature-key-08`.
  Both are IETF Internet-Drafts, not released standards; wire formats change
  between revisions.
- **[Source code]({{ site.repo_url }})** — Rust, MIT.

## Status, in one paragraph

Everything the drafts require of a Person Server is implemented and tested:
discovery and keys, inbound signature verification, passkey enrolment and
login, the dashboard, person tokens with the deferred (`202`) consent flow,
auth tokens with the seven-step resource-token check, inbound and outbound
revocation, missions, and four-party federation to an Access Server plus call
chaining. The last two are exercised against mock servers only — no live
Access Server exists in the ecosystem yet. Optional surfaces psd does not offer
(clarification chat, an interaction relay, permission and audit endpoints,
`mission_control_endpoint`, Postgres, OIDC login) are absent from its metadata,
which is how the protocol says "not supported".
