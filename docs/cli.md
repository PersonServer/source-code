---
title: Command line
description: The psd command line — serve, keygen, person, invite, agents, pending, example-config, version — with what each does to the record.
---

# Command line

<span class="audience">for operators</span>

```
psd serve [--config psd.json]
psd keygen [--keys psd-keys.json] [--rotate] [--prune-days N]
psd person add --name "Alice" [--config psd.json] [--ttl 900]
psd person list [--config psd.json]
psd invite --person ID [--config psd.json] [--ttl 900]
psd agents list [--config psd.json]
psd agents revoke ISS SUB [--config psd.json]
psd pending list [--config psd.json]
psd pending approve ID [--person ID] [--config psd.json]
psd pending deny ID [--config psd.json]
psd example-config > psd.json
psd version
```

Every command except `keygen`, `example-config` and `version` loads the
config (`--config`, default `psd.json`, plus the environment overrides) and
opens the database. Relative `storage.path` and `keys_file` resolve against
the current directory, so run these from where `serve` runs, or use
absolute paths. The CLI refuses a `:memory:` database, since there would be
nothing to operate on.

## `serve`

Runs the server on `listen` until `SIGINT`/`SIGTERM`. Prints a startup
summary to stderr — issuer, storage, whether passkeys are available
(they are not on an IP-address issuer), whether templates are overridden,
the tracked drafts, and a warning if `insecure_dev_mode` is on. Housekeeping
(expired sessions, enrolments and pending requests; retention purges) runs
inline and on a ten-minute tick.

## `keygen`

Creates the keys file (mode `0600`) with one active Ed25519 signing key and
the pairwise secret. On an existing file:

- `--rotate` adds a new key and makes it active. Old keys stay in the file
  and their public halves stay in the JWKS, so tokens signed before rotation
  (they live at most an hour) keep verifying. Restart `serve` afterwards.
- `--prune-days N` removes keys older than N days from the file (and thus
  from the JWKS). Prune well after rotation, never the active key.
- a file without a `pairwise_secret` gets one. An existing secret is never
  changed by anything — it is what keeps every directed `sub` stable.

Key ids are `ps-` followed by a random suffix.

## `person add`, `person list`, `invite`

`person add --name NAME` creates a person and prints a **one-time enrolment
link** on stdout (the explanation goes to stderr): opening it registers the
person's first passkey. `--ttl` sets its validity in seconds (default 900).
It warns when the issuer host is an IP address, because the link will not
be able to create a passkey there.

`invite --person ID` mints another link for an existing person — someone
who lost every device, or who was created before passkeys were possible.
Each link is single-use and expires.

`person list` prints one line per person: id, display name, passkey count,
created at.

## `agents list`, `agents revoke`

`agents list` prints every agent binding — agent `iss` and `sub`, the person
it is bound to, status, and when it was bound or revoked.

`agents revoke ISS SUB` does what the dashboard's **Revoke** button does,
attributed to the CLI in the audit record: marks the binding revoked (the
agent cannot obtain new tokens; it must be approved by the person again to
come back), revokes the consents recorded for it, marks its live auth tokens
revoked, and POSTs a signed revocation to every service that received one.
Already-revoked bindings are reported as such and left alone.

## `pending list`, `pending approve`, `pending deny`

For headless operation — a Person Server nobody is watching in a browser.

`pending list` prints every request waiting for a decision: id, kind
(`person`, `auth`, `mission`, `mission_completion`), agent, resource, who it
is for (or *unbound* for a new agent), and when it expires.

`pending approve ID` records the decision exactly as the person's browser
would — binds the agent, records consent, mints the token, resolves the
pending request so the agent's next poll returns it. Which person decides:
`--person ID` if given; otherwise the person the request is already claimed
by; otherwise, when exactly one person exists, that one (with several, the
command asks you to say). An agent actively bound to someone else is
refused — revoke that binding first. Missions are approved with the
configured default lifetime.

`pending deny ID` tells the agent no; nothing is issued or remembered.

Both are audited with `"via": "cli"` so the record distinguishes an
operator's decision from the person's own.

## `example-config`, `version`

`example-config` prints the [annotated starting config](configuration.md#the-example-config).
`version` prints the version and the draft revisions this build tracks:

```
psd 0.1.0 (tracking AAuth Internet-Drafts: draft-hardt-oauth-aauth-protocol-11, draft-hardt-httpbis-signature-key-08)
```
