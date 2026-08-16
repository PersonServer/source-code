# Changelog

## 0.2.0 — 2026-08-16

- **Enterprise SSO.** `person_auth.method = "oidc"`: people may also sign in
  through the organisation's OpenID Connect provider (Authorization Code +
  PKCE; Okta, Entra ID, Google Workspace, Keycloak, Auth0). Additive to
  passkeys, per person. Discovery at startup; `state`/`nonce` bound to a
  single-use sign-in row; ID tokens verified against the provider's keys
  (RSA/ECDSA/EdDSA); `required_claims` is the mandatory gate; persons keyed
  on the provider's `(iss, sub)` and provisioned just in time;
  `tenant_claim` → `tenant` in person tokens; `psd person deactivate` /
  `activate` for deliberate offboarding. New docs page: Identity providers.
- **Discovery failures are no longer `unknown_key`.** A metadata or JWKS
  fetch that fails (egress refused, DNS, timeout) — or the once-per-minute
  floor held by such a failure — is `503 temporarily_unavailable` with
  `Retry-After` and no `Signature-Error`, plus a `discovery_unavailable`
  audit event, on every endpoint that discovers keys. `unknown_key` is
  reserved for a fetched key set that lacks the `kid`.
- **Schema v2.** `person.status`, `person.tenant`, `person_identity`,
  `oidc_login`; a v1 database is migrated on open. Take a backup before
  upgrading.
- **Chart.** `dnsConfig` value, defaulting to `ndots: 1`, because a pod
  search domain plus a wildcard DNS record can resolve an external Agent
  Provider hostname to a private address that egress admission refuses.
- **Interop.** The pre-11 resource-token claim name `person_token_jti` is
  accepted as `presented_jti` (whoami.aauth.dev still emits it). Chart:
  ingress `proxy-read-timeout` 60 s by default so `Prefer: wait` long polls
  are not cut off by the proxy.
- Audit: `signed_in` carries `method` (`passkey` / `oidc`); the API
  reference documents the problem-details member as `detail` (it always
  was).
- 129 tests.

## 0.1.0 — 2026-08-15

First release: the Person Server role of `draft-hardt-oauth-aauth-protocol-11`
(discovery and keys, RFC 9421 verification, passkey enrolment and login,
dashboard, person tokens with the deferred consent flow, auth tokens with the
seven-step resource-token check, inbound and outbound revocation, missions,
four-party federation and call chaining — the last two mock-tested only),
multi-arch image, OCI Helm chart, personserver.dev.
