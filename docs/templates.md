---
title: Templates & branding
description: Every screen psd renders is a MiniJinja template embedded in the binary; point ui.templates_dir at a directory to override any of them by file name.
---

# Templates & branding

<span class="audience">for operators</span>

psd's pages — enrolment, login, dashboard, consent, activity, passkeys,
errors — are server-rendered from [MiniJinja](https://docs.rs/minijinja)
templates (Jinja2 syntax) that are **embedded in the binary**. There is no
SPA, no build step, and no JavaScript beyond one small file that drives the
WebAuthn ceremonies. To restyle or rewrite any screen, put a file with the
same name in a directory and set `ui.templates_dir` to it:

```json
{ "ui": { "templates_dir": "/etc/psd/templates" } }
```

Templates are loaded once at startup. A file present in the directory
replaces the built-in of that name; anything absent falls back to the
built-in, so overriding only `base.html` (your logo, colours and footer)
restyles every page. A missing directory is a startup error; a partial one
is normal.

## The templates

| File | Renders | Notable variables |
|---|---|---|
| `base.html` | the frame every page extends: header with `ps_name`, nav for a signed-in `person`, footer with `version` and `issuer` | `ps_name`, `person` (`id`, `display_name`), `issuer`, `version`, `csrf` — available in every template |
| `enrol.html` | the one-time enrolment page (**Create passkey**), also reused for adding a passkey | `display_name`, `adding`, `options_url`, `finish_url`, `csrf` |
| `login.html` | passkey sign-in | `next` |
| `dashboard.html` | pending decisions, agents with revoke, missions with log and end, consents, recent activity, the code box | `pending[]`, `bindings[]`, `missions[]`, `consents[]`, `audit[]` |
| `activity.html`, `activity_rows.html` | the full activity page and the row partial the dashboard includes | `audit[]` |
| `passkeys.html` | the person's credentials, add button | `credentials[]` |
| `consent_code.html` | "Enter the code your agent showed you" | `error` |
| `consent.html` | the consent screen for every kind: `person`, `auth`, `mission`, `mission_completion` | `kind`, `new_agent`, `agent_sub`, `agent_iss`, `ap_name`, `ap_logo_uri`, `platform`, `device`, `subagent_sub`, `chained`, `resource`, `resource_meta` (`name`, `description_html`, `access_mode`, `logo_uri`), `scopes[]` (`name`, `description_html`), `justification_html`, `mission` (`description_html`, `tools[]`, `resources[]`, `s256`, `summary_html`), `default_ttl_secs`, `details_json`, `csrf` |
| `consent_done.html` | the result page after a decision | `approved`, `kind`, `agent_sub`, `resource` |
| `error.html` | any error page | `title`, `detail` |

Everything named `*_html` has already been through psd's whitelist
Markdown renderer (no raw HTML, links as text) and is safe to output with
the `| safe` filter, as the built-ins do. Everything else is auto-escaped;
MiniJinja's autoescape is on for every template, so a value can never
inject markup unless you `| safe` it yourself. A `datetime` filter formats
Unix timestamps.

The safest way to start is to copy the built-ins from the repository's
[`crates/psd/templates`](https://github.com/PersonServer/source-code/tree/main/crates/psd/templates)
and edit.

## Keep the security properties

The built-ins are written to work under psd's response headers, and your
overrides must be too:

- **Strict CSP, no inline script.** Every page is served with
  `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'
  https:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`.
  An inline `<script>`, `<style>` or `onclick` will not run; scripts and
  stylesheets must come from the issuer origin (`'self'`), images may come
  from any `https:` URL. Passkeys are driven by `/static/passkey.js`, which
  reads its endpoints from `data-*` attributes on the buttons
  (`data-options`, `data-finish`, `data-csrf`, `data-next`); keep those
  attributes and the ids `passkey-create` and `passkey-get`.
- **CSRF on every form.** Every POST form must carry
  `<input type="hidden" name="csrf" value="{{ csrf }}">`. Forms without it
  are refused.
- **The consent screen must keep saying what it says.** The protocol
  requires the person be shown the agent, its provider, the resource, and
  the terms; the built-in marks agent-supplied fields as unverified and
  labels the agent's own words. Restyle it freely; do not drop those
  labels — they are what makes the decision informed.
- **Static assets.** psd serves its own CSS and `passkey.js` from
  `/static/`. To ship your own stylesheet or logo, host it under the issuer
  origin behind your proxy (for instance at `/branding/…`, which psd does
  not route) and reference it from `base.html`; `'self'` in the CSP then
  admits it. A logo may also be any `https:` image.

## Server metadata is branding too

`metadata.name`, `description`, `logo_uri`/`logo_dark_uri`,
`documentation_uri`, `tos_uri`, `policy_uri` are published in
`/.well-known/aauth-person.json` and shown on psd's own pages, and Agent
Providers and agents show them to *their* users when explaining where a
person's consent is being asked. Set at least `name` and `logo_uri`.
