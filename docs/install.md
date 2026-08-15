---
title: Install & deploy
description: Operator guide for psd — build or pull it, choose the permanent issuer, create keys, put TLS in front, add the first person, and run it day to day.
---

# Install & deploy

<span class="audience">for operators</span>

psd is one static binary, one keys file and one SQLite database. This page
takes you from nothing to a Person Server that agents can find and people
can log in to, then covers day-two operations. Every configuration field is
in the [configuration reference](configuration.md); every command in the
[CLI reference](cli.md).

## Before you start: three decisions that are hard to undo

**The issuer is permanent.** `issuer` (for example `https://ps.example.com`)
goes into every pairwise `sub` psd derives and into `iss` of every token it
signs. Change it and every service sees a stranger and every agent must be
approved again. It must be an `https://` origin — lowercase, no port, no
path — and this exact origin must serve `/.well-known/aauth-person.json`.

**It must be a hostname, not an address.** People log in with passkeys, and
browsers refuse to create passkeys on IP-address origins. In development
that means `http://localhost:8430`, never `http://127.0.0.1:8430`.

**The keys file is the identity, and the pairwise secret inside it must
never change.** `psd keygen` writes the Ed25519 signing keys *and* the
`pairwise_secret` used to derive per-service identifiers to one file. Losing
the file means every service sees new strangers; leaking it means someone
else can sign as your server. Back it up like a private key, because it is
one.

## Get the binary

Pick one.

**From source** (Rust 1.85+; SQLite is compiled in, so a C compiler is the
only system dependency):

```sh
git clone https://github.com/PersonServer/source-code psd && cd psd
cargo build --release
./target/release/psd version
```

**Container image**, multi-arch (amd64, arm64), distroless, non-root:

```sh
docker pull ghcr.io/personserver/psd:latest      # or :edge for the latest main
```

**Helm chart** (OCI), single replica with a persistent volume:

```sh
helm install psd oci://ghcr.io/personserver/charts/psd \
  --set issuer=https://ps.example.com --set keys.existingSecret=psd-keys
```

The chart's [README](https://github.com/PersonServer/source-code/tree/main/charts/psd)
covers its values; the rest of this page applies to it as much as to a bare
binary.

## 1 · Create the keys

```sh
psd keygen --keys /var/lib/psd/psd-keys.json
# created /var/lib/psd/psd-keys.json with new active key 'ps-…' and a pairwise secret
```

The file is written `0600`. Its shape is a JSON object with the active
`kid`, the private keys, and the pairwise secret; there is nothing in it you
ever paste anywhere else. Rotation is covered below.

## 2 · Write the config

```sh
psd example-config > /etc/psd/psd.json
```

Edit at least these:

```json
{
  "issuer": "https://ps.example.com",
  "listen": "127.0.0.1:8430",
  "keys_file": "/var/lib/psd/psd-keys.json",
  "storage": { "backend": "sqlite", "path": "/var/lib/psd/psd.db" },
  "metadata": {
    "name": "Example Person Server",
    "description": "Manage which agents act for you and review what they do.",
    "documentation_uri": "https://personserver.dev/docs/"
  }
}
```

Unknown fields are hard errors and every value is validated at load, with a
message that says what to change — a typo will not become a silently
ignored setting. `metadata.name` is what people see on every screen; set it.
Everything else has a sensible default; see the
[reference](configuration.md) when you want to change one.

Secrets and hostnames can be injected by the environment instead of edited
into the file: `PSD_ISSUER`, `PSD_LISTEN`, `PSD_KEYS_FILE`, `PSD_DB_PATH`
win over the file.

## 3 · Put TLS in front

psd speaks plain HTTP on `listen`; terminate TLS in a reverse proxy or
ingress. Three rules, each with a reason:

- **Preserve the `Host` header.** Agents sign `@authority` on every request
  and psd checks it against the issuer host before doing anything else. A
  proxy that rewrites `Host` to `127.0.0.1:8430` breaks every signed
  request. If you truly cannot preserve it, set `expected_authority` to
  what the proxy sends — but preserving it is the fix.
- **No path rewriting.** `/.well-known/aauth-person.json`, `/person`,
  `/token` and the rest must be reachable at exactly those paths on the
  issuer origin. Serve psd at the root of its own hostname.
- **Pass bodies through unchanged.** Signed requests cover a
  `Content-Digest` of the body; a proxy that re-encodes JSON will break the
  signature. Normal proxies do not.

A minimal nginx site:

```nginx
server {
    listen 443 ssl http2;
    server_name ps.example.com;
    # ssl_certificate …; ssl_certificate_key …;
    location / {
        proxy_pass http://127.0.0.1:8430;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
    }
}
```

Caddy does the right thing with `reverse_proxy 127.0.0.1:8430`. On
Kubernetes, the chart's Ingress preserves `Host` with every mainstream
controller's defaults.

## 4 · Serve

```sh
psd serve --config /etc/psd/psd.json
```

Startup prints what it is doing — issuer, listen address, storage, whether
passkeys are available (they are not on an IP-address issuer), whether
templates are overridden, which drafts it tracks — and then serves. Check
from outside:

```sh
curl -s https://ps.example.com/healthz
curl -s https://ps.example.com/.well-known/aauth-person.json
curl -s https://ps.example.com/.well-known/jwks.json
```

The metadata document is what agents (and Agent Providers, and services)
discover; if it does not load at the issuer origin, nothing else will work.

A systemd unit that matches the layout above:

```ini
[Unit]
Description=psd — AAuth Person Server
After=network-online.target
Wants=network-online.target

[Service]
User=psd
Group=psd
ExecStart=/usr/local/bin/psd serve --config /etc/psd/psd.json
WorkingDirectory=/var/lib/psd
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/psd
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

CLI commands take `--config`; relative paths in the config resolve against
the current directory, so run them from `WorkingDirectory` (or use absolute
paths, as the examples here do).

## 5 · Add the first person

```sh
psd person add --name "Alice" --config /etc/psd/psd.json
# https://ps.example.com/enrol/…
# created person … (Alice); open the link above within 900s to register a passkey (single use)
```

The link goes to stdout and the explanation to stderr, so it scripts
cleanly. `--ttl` changes the 15-minute default.

Send the link to Alice (or open it yourself). It shows *"Welcome, Alice"*
and a **Create passkey** button; after that she is enrolled and on her
dashboard. `psd invite --person ID` mints another link later — for a person
who lost every passkey, for instance. `psd person list` shows who exists.

That is a working Person Server. Point an agent at it — the quickest real
one is an agent enrolled at
[agentprovider.dev's sandbox](https://agentprovider.dev/docs/sandbox.html);
`apd`'s `tools/aauthcheck --target https://ps.example.com --poll` walks the
whole deferred flow — approve the request on Alice's dashboard, and the
agent receives its person token.

## Day two

### Headless approvals

When nobody is watching a browser, decisions can be made from the shell:

```sh
psd pending list --config /etc/psd/psd.json
psd pending approve <id> --config /etc/psd/psd.json     # --person ID if unbound
psd pending deny <id> --config /etc/psd/psd.json
```

They are recorded in the audit log with `"via": "cli"`, so the record shows
the operator decided, not the person's browser. `psd agents list` and
`psd agents revoke ISS SUB` do the same for bindings; a CLI revocation
revokes the agent's consents and sweeps its auth tokens at their services
just as the dashboard button does.

### Notifications

By default a pending request simply waits on the dashboard. Add
`"webhook"` to `notify.channels` and set an `https://` `notify.webhook_url`
to receive a JSON POST when a decision is pending — enough to page someone
or forward to chat. The webhook never carries the interaction code.

### The record

Every issuance, denial, revocation, binding and mission event is one JSON
line on stderr, and the same event as a row the person sees under
*Activity*. Set `audit_log_file` to also append the lines to a file. Two
events deserve an alert if you have one: `resource_token_mismatch` (a
service presented a resource token that names a person token psd issued —
but for a different agent, person or mission; the service is confused or
hostile) and repeated `person_token_denied` with `reason: too_many_resources`
(an agent probing many services). A third, `discovery_unavailable`, means
psd could not fetch an issuer's metadata or JWKS and answered the agent
`503`: usually your egress (DNS, firewall, a proxy that rewrites responses),
sometimes their outage — either way the agent is not at fault, and the
event names the issuer and the reason.

### Backups

Two files: the keys file and the SQLite database (`psd.db`, plus its `-wal`
and `-shm` while running). The database holds person records, passkey
public keys, bindings, consent history and the directed identifiers — it is
personal data; treat backups accordingly. psd runs SQLite in WAL mode, so
copying the file while serving is safe as long as you copy `psd.db` and
`psd.db-wal` together (or use `sqlite3 psd.db ".backup out.db"`).

### Key rotation

```sh
psd keygen --keys /var/lib/psd/psd-keys.json --rotate           # new active key
psd keygen --keys /var/lib/psd/psd-keys.json --prune-days 30    # drop old ones
```

Rotation adds a new active key; old public keys stay in the JWKS until
pruned, so tokens signed before rotation (they live at most an hour) keep
verifying. psd re-reads the file at start — restart after rotating. The
pairwise secret is untouched by rotation and must stay so.

### Upgrades

Stop, replace the binary (or image tag), start. The schema is created and
extended at startup. Take a database backup before upgrading; AAuth is a
draft, so pin a version, read the release notes, and expect wire changes
between draft revisions.

### Development mode

For local work set `"insecure_dev_mode": true` and an `http://host:port`
issuer such as `http://localhost:8430`. That relaxes the identifier rules,
admits loopback and plain-HTTP egress so a mock Agent Provider on
`127.0.0.1` works, and permits a non-`Secure` session cookie. `serve` prints
a warning while it is on. Never enable it where anyone else can reach the
server.

### Optional surfaces

`missions.enabled` advertises `mission_endpoint` and turns on the mission
flow; `federation.enabled` turns on four-party federation to an Access
Server and call chaining. Both default to off. Federation is exercised
against a mock Access Server only — no live one exists yet — so enable it
knowingly.

## What psd expects from you

- A stable hostname with TLS in front, `Host` preserved.
- The keys file kept secret and backed up; the database backed up.
- Someone who reads the audit line about `resource_token_mismatch`.
- A version pin and a glance at release notes: the protocol is a draft.
