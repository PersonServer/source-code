---
title: Configuration
description: Every field of psd.json, its default, and the protocol rule behind it; environment overrides; the example config.
---

# Configuration

<span class="audience">for operators</span>

psd reads one JSON file (`serve --config`, default `psd.json`) plus a
handful of environment overrides. `psd example-config` prints a starting
point ([the file itself](psd.example.json)). Every struct rejects unknown
fields and every value is validated at load, so a typo is a startup error
with a message that says what to change, never a silently ignored setting.

Merge order is fixed: **file → environment → validate**. The environment
wins over the file so a deployment can inject a hostname or a path without
editing it.

## Environment overrides

| Variable | Overrides |
|---|---|
| `PSD_ISSUER` | `issuer` |
| `PSD_LISTEN` | `listen` |
| `PSD_KEYS_FILE` | `keys_file` |
| `PSD_DB_PATH` | `storage.path` |
| `PSD_TELEMETRY_ENABLED` | `telemetry.enabled` (`1` or `true`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `telemetry.endpoint` (only when unset in the file) |
| `OTEL_SERVICE_NAME` | `telemetry.service_name` (only when unset in the file) |

## Top level

| Field | Default | Meaning |
|---|---|---|
| `issuer` | *(required)* | The server identifier: `https://host`, lowercase, no port, no path, no trailing slash. **Permanent** — it is in every derived `sub` and every token's `iss`, and this exact origin must serve `/.well-known/aauth-person.json`. Must be a hostname: passkeys do not work on IP-address origins. |
| `listen` | `127.0.0.1:8430` | Bind address. Use `0.0.0.0:8430` in a container. |
| `keys_file` | `psd-keys.json` | The file `psd keygen` writes: signing keys plus the pairwise secret. Read at startup. |
| `expected_authority` | *(issuer host)* | The `@authority` (`Host`) inbound signed requests must carry. Set only when a TLS-terminating proxy rewrites `Host` — better to make it preserve `Host`. The check is what makes the mandated `@authority` component prevent cross-host replay, so it is never simply off. Lowercase host, optional `:port`. |
| `insecure_dev_mode` | `false` | **Development only.** Accepts an `http://` issuer (and ports), allows outbound fetches over `http` and to private/loopback addresses, permits a non-`Secure` session cookie. `serve` warns while it is on. |
| `max_body_bytes` | `65536` | Largest request body accepted (min 1024). |
| `jwks_cross_origin_hosts` | `[]` | Bare hostnames admitted as cross-origin `jwks_uri` hosts when verifying foreign tokens (an issuer whose metadata points its JWKS at a CDN) and for the SSO provider's keys (Google Workspace: `www.googleapis.com`). Empty means same-origin JWKS only, per the Signature-Key draft. |
| `audit_log_file` | *(unset)* | Append the structured JSON audit events to this file, in addition to stderr. |

## Token lifetimes and windows

| Field | Default | Meaning |
|---|---|---|
| `person_token_ttl_secs` | `3600` | Person-token lifetime. The draft says person tokens MUST NOT live longer than one hour, so `1..=3600`. The issued `exp` is further capped by the presenting agent token's `exp` and, under a mission, by the mission's `expires_at`. |
| `auth_token_ttl_secs` | `3600` | Auth-token lifetime, same one-hour ceiling and the same caps. |
| `signature_window_secs` | `60` | How far a request signature's `created` may be from now (`1..=3600`). Also the window of the replay guard on body-carrying requests. |
| `resource_token_max_age_secs` | `300` | The longest resource-token lifetime (`exp − iat`) accepted at `/token` (`1..=3600`; the draft says resource tokens SHOULD NOT exceed five minutes). This is also the retention **floor**: person-token records are kept at least this long past their `exp`, so a resource token naming one can still be checked. |
| `retention_slack_secs` | `3600` | Extra retention beyond the floor for clock skew and slack. A person-token record is purged after `exp + resource_token_max_age_secs + retention_slack_secs`; forgotten early, a valid resource token is wrongly refused; never forgotten, the table grows without bound. |

## `storage`

| Field | Default | Meaning |
|---|---|---|
| `storage.backend` | `sqlite` | The only backend in this build. `postgres` is planned and **rejected** at load, so a deployment cannot believe it is using it. |
| `storage.path` | `psd.db` | SQLite file. `:memory:` is accepted for tests and throwaway runs (state is lost at exit; the CLI refuses it). psd opens it in WAL mode. |

## `directed_sub`

| Field | Default | Meaning |
|---|---|---|
| `directed_sub.mode` | `pairwise` | The only mode: `sub` is derived per (person, audience) with the pairwise secret, so two services cannot correlate a person. Any other value is rejected. |

## `person_auth` — passkeys, and single sign-on

| Field | Default | Meaning |
|---|---|---|
| `person_auth.method` | `passkey` | `passkey`: people sign in with passkeys only. `oidc`: people may **also** sign in through the organisation's OpenID Connect provider configured in `person_auth.oidc`. Additive, per person — existing passkeys keep working, new ones can still be added, enrolment links still work, and the login page shows both. There is deliberately no way to turn passkeys off: that switch's failure mode is silently locking people out, and an operator wants a break-glass passkey for when the provider is down. |

`person_auth.oidc` (required when `method` is `oidc`; psd is an OIDC Relying
Party using Authorization Code + PKCE):

| Field | Default | Meaning |
|---|---|---|
| `oidc.issuer` | *(required)* | The provider's issuer URL, e.g. `https://acme.okta.com`, `https://login.microsoftonline.com/<tenant>/v2.0`, `https://accounts.google.com`, `https://keycloak.example/realms/acme`. `https://`, no trailing slash. Discovery (`/.well-known/openid-configuration`) runs at startup through psd's egress admission and the document's `issuer` must equal this value byte for byte; a typo, an unreachable provider or a wrong secret path fails startup, not the first login. |
| `oidc.client_id` | *(required)* | The client registered at the provider. Its redirect URI is **`{issuer}/login/oidc/callback`** — psd prints it at startup; register exactly that. |
| `oidc.client_secret_file` | *(required)* | File holding the client secret (one line). A file for the same reason `keys_file` is: it stays out of the config and out of every debug print. |
| `oidc.scopes` | `["openid","profile","email"]` | Must include `openid`. |
| `oidc.required_claims` | *(required, non-empty)* | Who may sign in: ID-token claim path → exact string, trailing-`*` prefix, or an array of those (any of). Array-valued claims such as `groups` match when any element does; an empty array never does. **This is the authorization gate and it is mandatory** — without it every account at the provider could sign in and (with provisioning on) get a person. "Everyone in our domain" is written explicitly: `{"hd": "acme.com"}` for Google Workspace, `{"groups": "psd-users"}` for a group, `{"realm_access.roles": "psd"}` for a Keycloak role. |
| `oidc.tenant_claim` | *(unset)* | An ID-token claim naming the person's organisation (`org_id`, `tid`, `hd`, …). Its value is stored on the person, refreshed at every SSO sign-in, and issued into every person token as `tenant` (organisational context; never part of the identifier), from where the resource token and auth token carry it — a resource applies org policy without knowing your provider. After an org move, tokens minted before the next sign-in carry the old value until they expire (at most an hour). |
| `oidc.display_name_claims` | `["name","preferred_username","email"]` | Tried in order for a newly provisioned person's display name. |
| `oidc.provision` | `true` | Create a person on first sign-in when no person is linked to the identity (just-in-time). `false`: only identities an existing person connected from their sign-in-methods page may sign in. |

Provider-by-provider settings (Okta, Entra ID, Google Workspace, Keycloak,
Auth0) and the failures each makes likely are in
[Identity providers](identity-providers.md). Identities are keyed on the
provider's `(issuer, sub)`, never on email —
email is mutable and reassignable, and an offboarded `alice@` handed to a
new Alice must not inherit the old Alice's agents and consents. Google
Workspace publishes its keys on `www.googleapis.com`; list that host in
`jwks_cross_origin_hosts`. Offboarding is a deliberate step —
[`psd person deactivate`](cli.md#person-deactivate-person-activate) — because
the provider deactivating a leaver stops their logins but not the agents
already acting for them.

## `notify`

| Field | Default | Meaning |
|---|---|---|
| `notify.channels` | `["web"]` | How the person is reached when a decision is pending. `web`: it waits on the dashboard. `webhook`: additionally POST a JSON notification to `webhook_url`. At least one channel is required. |
| `notify.webhook_url` | *(unset)* | Required, and must be `https://`, when `webhook` is listed (`http://` only in dev mode). The payload names the pending request, the agent and the resource; it never carries the interaction code. |

## `missions` and `federation`

| Field | Default | Meaning |
|---|---|---|
| `missions.enabled` | `false` | Advertise and serve `mission_endpoint`. Off by default: presence of the endpoint in metadata is how a Person Server says it supports missions. When off, `mission_s256` on `/person` is refused as an unsupported parameter rather than silently ignored. |
| `missions.default_ttl_secs` | `86400` | The lifetime pre-selected on the mission approval screen. The person may choose a shorter or longer one, or none. |
| `federation.enabled` | `false` | Four-party: when a resource token's `aud` names an Access Server, obtain the person's consent and then federate to it; also enables call chaining via `upstream_token`. Exercised against a mock Access Server only, since no live one exists yet. |

## `limits`

| Field | Default | Meaning |
|---|---|---|
| `limits.resources_per_agent_per_day` | `50` | Distinct `resource` values one agent may obtain person tokens for per rolling day (the draft says a PS SHOULD rate-limit: each obliges a derived and retained directed `sub`). A resource the agent already holds a token for is never counted. Over the limit: `429` with `Retry-After`. |
| `limits.code_attempts` | `5` | Failed interaction-code presentations before the pending interaction is terminally failed (the draft says the PS MUST rate-limit code validation). |
| `limits.pending_ttl_secs` | `600` | How long a deferred request waits for the person before it expires (min 30). |

## `ui`

| Field | Default | Meaning |
|---|---|---|
| `ui.session_ttl_secs` | `43200` | Browser session lifetime (min 60). Sessions are `HttpOnly; SameSite=Lax; Secure` cookies with a CSRF token on every POST. |
| `ui.templates_dir` | *(unset)* | Directory of HTML templates that override the built-in ones by file name (consent screen, dashboard, …). Built-ins are embedded and used for anything not present. Loaded at startup; a missing directory is an error, a partial one is fine. See [Templates & branding](templates.md). |

## `metadata`

Display fields published in `/.well-known/aauth-person.json` and shown on
psd's own screens. All optional; every URI must be `https://`.

| Field | Meaning |
|---|---|
| `metadata.name` | The server's human name — on every page title and the consent screen. Set it. |
| `metadata.description` | Markdown, one or two sentences. Consumers must sanitize before rendering; psd does the same with theirs. |
| `metadata.logo_uri`, `metadata.logo_dark_uri` | Logos for light and dark themes. |
| `metadata.documentation_uri` | Where a reader learns what this server is. The example config points at `https://personserver.dev/docs/`. |
| `metadata.tos_uri`, `metadata.policy_uri` | Terms and privacy policy. |

## `telemetry`

Accepted and validated now so a file written for the release that wires it
in parses today; **not yet emitting** anything.

| Field | Default | Meaning |
|---|---|---|
| `telemetry.enabled` | `false` | Master switch (`PSD_TELEMETRY_ENABLED`). |
| `telemetry.endpoint` | *(unset)* | OTLP/HTTP base, `http://` or `https://` (`OTEL_EXPORTER_OTLP_ENDPOINT`). |
| `telemetry.service_name` | `psd` | (`OTEL_SERVICE_NAME`) |
| `telemetry.metric_interval_secs` | `30` | |

## The example config

`psd example-config` prints this; [`psd.example.json`](psd.example.json) is
the same file.

```json
{
  "issuer": "https://ps.example.com",
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
  "limits": { "resources_per_agent_per_day": 50, "code_attempts": 5, "pending_ttl_secs": 600 },
  "ui": { "session_ttl_secs": 43200, "templates_dir": null },

  "missions": { "enabled": false },
  "federation": { "enabled": false },

  "metadata": {
    "name": "Example Person Server",
    "description": "Manage which agents act for you and review what they do.",
    "documentation_uri": "https://personserver.dev/docs/"
  },
  "telemetry": { "enabled": false, "endpoint": "http://localhost:4318" },
  "insecure_dev_mode": false
}
```

## The keys file

Written by `psd keygen`, mode `0600`, and read at startup:

```json
{
  "active": "ps-…",
  "keys": [ { "kid": "ps-…", "d": "<base64url Ed25519 seed>", "created_at": 1755000000 } ],
  "pairwise_secret": "<base64url 32 bytes>"
}
```

`--rotate` adds a new active key and keeps the old ones (their public halves
stay in the JWKS so tokens signed before rotation still verify);
`--prune-days N` drops keys older than N days. `keygen` on an existing file
that lacks a `pairwise_secret` adds one. Nothing ever changes an existing
`pairwise_secret`: it is what makes every directed `sub` stable.
