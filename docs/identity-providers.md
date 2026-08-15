---
title: Identity providers
description: Configuring psd's single sign-on against Okta, Microsoft Entra ID, Google Workspace, Keycloak and Auth0 — the operator contract, the predictable failures, and a first-tenant checklist.
---

# Identity providers

<span class="audience">for operators</span>

psd's single sign-on is generic OpenID Connect (Authorization Code + PKCE;
see the [configuration reference](configuration.md#person_auth--passkeys-and-single-sign-on)
for every field). "Support for provider X" is therefore not a code path —
it is knowing the shape of X's documents, the failures X makes likely, and
the two or three settings that differ. This page is that knowledge, Okta
first because it is the one most orgs bring.

What every provider has in common:

- psd is registered as a **web application** with the redirect URI
  `{issuer}/login/oidc/callback` (psd prints the exact value at startup).
- **There is no audience setting.** psd validates the ID token's `aud`
  against `client_id`; that is the whole contract. (If you also run
  [apd](https://agentprovider.dev), note that *its* admin SSO has an
  `audience` that means an API audience, not a client id — the two are
  not interchangeable.)
- **`required_claims` is mandatory** and is the whole authorization gate.
  A claim that is *absent* from the ID token and a claim that is present but
  *does not match* are reported differently, because they send you to
  different screens: `ID token has no 'groups' claim; the identity
  provider is not sending it` versus `'groups' does not include a
  permitted value`.
- Persons are keyed on the provider's `(iss, sub)`, never email. `sub` is
  usually opaque (`00u1a2b3…`); psd stores `email` for display and puts it
  in the sign-in audit line.
- Offboarding at the provider stops sign-ins, not agents:
  [`psd person deactivate`](cli.md#person-deactivate-person-activate).

## Okta

**Issuer.** Okta has two kinds of authorization server and both work for
psd, because psd consumes an *ID token* whose `aud` is the client id — it
does not need a custom audience:

- the **org** authorization server, `https://acme.okta.com` (or your
  custom domain);
- a **custom** authorization server, `https://acme.okta.com/oauth2/default`
  (needs API Access Management; `default` exists on developer orgs).

Either value goes in `oidc.issuer` exactly as Okta shows it under *Security
→ API → Authorization Servers* — no trailing slash. Discovery is the issuer
plus `/.well-known/openid-configuration` in both cases, and every endpoint
comes from that document.

**Application.** *Applications → Create App Integration → OIDC → Web
Application*, sign-in redirect URI `https://ps.example.com/login/oidc/callback`,
grant type *Authorization Code*. Copy the client id and secret; put the
secret in `client_secret_file`. Client authentication is
`client_secret_basic`, Okta's default.

**Groups — the most predictable failure.** Okta does not put `groups` in an
ID token until you say so. With `required_claims: {"groups": "psd-users"}`
and no groups claim configured, *every* sign-in is refused with
`ID token has no 'groups' claim; the identity provider is not sending it`.
The fix is on the application, not on the person: *Applications → your app
→ Sign On → OpenID Connect ID Token → Groups claim type: Filter → Groups
claim filter: `groups` · Matches regex · `^psd-`* (or *Equals `psd-users`*).
Keep the filter narrow: Okta caps the groups claim in an ID token, and a
person in more groups than the cap (about a hundred) gets **no groups claim
at all** — which denies exactly the most heavily-permissioned accounts,
usually the admin doing the testing. A dedicated `psd-users` group with a
filter that emits only it keeps the array small by construction.

**`Everyone`.** Every Okta user is in the `Everyone` group.
`{"groups": "Everyone"}` passes psd's non-empty check and authorizes the
whole directory — an empty gate wearing a costume. Do not write it.

**Custom domains.** `login.acme.com` and `acme.okta.com` are different
issuers; the token's `iss` is whichever the application uses. If psd says
the ID token's issuer is not the configured provider, this is the usual
cause — a copy-paste, not an attack.

**Tenant.** Okta has no organisation claim by default; if you want
`tenant` in tokens, add a custom claim (e.g. `org` from a profile
attribute) and set `tenant_claim` to it.

**Key rotation** is automatic and needs nothing from you: an unknown `kid`
makes psd refetch the JWKS (at most once a minute).

## Microsoft Entra ID

- `oidc.issuer`: `https://login.microsoftonline.com/<tenant-id>/v2.0`
  (the v2.0 endpoint; the tenant id, not `common`, so `iss` is exact).
- App registration: *Web* platform, the redirect URI, a client secret. ID
  tokens are RS256.
- Groups: enable *Token configuration → Add groups claim* (security
  groups, emitted as object ids — so `required_claims: {"groups":
  "<group-object-id>"}`), or prefer **app roles** assigned to a group and
  gate on `roles`. Entra **omits `groups` entirely** for users in more than
  ~150 groups (it emits `_claim_names`/`_claim_sources` instead), so a
  broad group gate fails for the most-permissioned users; app roles do not
  have this problem.
- Tenant: `tenant_claim: "tid"`.

## Google Workspace

- `oidc.issuer`: `https://accounts.google.com`.
- Google publishes its keys on a different host: add
  `"jwks_cross_origin_hosts": ["www.googleapis.com"]` or discovery will
  refuse the JWKS as cross-origin.
- Gate on the hosted domain: `required_claims: {"hd": "acme.com"}` — the
  explicit way to say "everyone in our domain". Google has no groups claim
  in ID tokens.
- Tenant: `tenant_claim: "hd"`.

## Keycloak

- `oidc.issuer`: `https://kc.acme.example/realms/<realm>`.
- Groups and roles: map a client scope; realm roles arrive as
  `realm_access.roles`, so `required_claims: {"realm_access.roles":
  "psd-user"}` (dotted paths resolve).
- Client authentication: *Client authentication: On*, credentials tab for
  the secret.

## Auth0

- `oidc.issuer`: `https://<tenant>.auth0.com` — Auth0 shows its issuer
  **with a trailing slash**; psd refuses that form (discovery is the issuer
  plus a suffix, and `iss` is compared exactly). Drop the slash.
- Custom claims are namespaced URLs; a claim path such as
  `https://acme.example/groups` resolves as a literal key.

## First-tenant checklist

Before pointing a real tenant at a production psd:

1. `psd serve` starts and prints `sign-in: passkeys + OpenID Connect (…)`
   with the redirect URI you registered. A wrong issuer, secret path or
   unreachable provider fails here.
2. Sign in as yourself. The consent screen still asks you when an agent
   asks — signing in is not consent.
3. Sign in as a **colleague who should not have access**. A gate nobody has
   tested from outside is not known to be a gate. Their refusal page should
   read `'groups' does not include a permitted value` (or your claim), and
   the audit line `oidc_login_denied` should name it.
4. Read one `signed_in` audit line and check `method`, `idp_iss`, `idp_sub`
   and `email` are what you expect.
5. Deactivate a test person at the provider *and* run
   `psd person deactivate` — and write both steps into the offboarding
   runbook.
6. Keep one passkey for an operator that does not go through the provider.
