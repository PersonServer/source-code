---
title: Using your Person Server
description: For the person — enrolling with a passkey, reading a consent screen, the dashboard, revoking an agent, missions, and what your Person Server never does.
---

# Using your Person Server

<span class="audience">for people</span>

Someone — you, a family member, your organisation — runs a Person Server for
you. Its job is to make sure that no AI agent acts as you anywhere without
your say-so, and to keep a record you can read. This page is what you will
see and what each choice means. If you are the one *running* it, the
[operator guide](install.md) is next door.

## Enrolling

You start with a **one-time enrolment link**, something like
`https://ps.example/enrol/…`. It was created for you by the operator (or by
yourself with `psd person add`) and is good for a short while, once.

Opening it shows *"Welcome, \<your name\>"* and one button: **Create
passkey**. There is no password to choose. Your browser or phone will ask you
to confirm with the method you already use to unlock it — Face ID, Touch ID,
Windows Hello, a hardware key — and that becomes your way in.

<div class="callout" markdown="1">
**Passkeys need a hostname.** Your Person Server must be reached at a name
like `ps.example`, not at an IP address; browsers refuse to create passkeys on
raw addresses. If the page says it cannot create one, tell whoever runs it.
</div>

Once enrolled you land on your dashboard. Add a second passkey — another
device, a hardware key — from **Passkeys → Add a passkey** so that losing one
device does not lock you out.

## When an agent asks

An agent that wants to act for you does not get to just do so. It asks your
Person Server, and unless you have already allowed that agent at that
service, the request is parked and you are asked. You get to it in one of
three ways:

- The agent shows you a **link and a short code** (letters and digits, like
  `7XK4-M2QP`). Open the link; if it does not carry the code already, type it
  on the **Enter the code** page. The code only *finds* the request — nothing
  is decided until you choose on the next page.
- You open your dashboard and see **Waiting for your decision** at the top.
- If your operator turned on webhook notifications, the notification links
  you to it.

Then you see the consent screen.

## Reading a consent screen

The heading is the question. Usually it is **"Allow this agent to act at
this service as you?"** — the plainest form of consent, an *identity*
decision. Below it:

**Agent** — the agent's identifier, something like
`aauth:k7q3p9n2@sandbox.agentprovider.dev`. **Agent provider** — the service
that vouches for the agent's identity, shown with its own name and logo when
it publishes them. This part *is* verified: the agent proved it holds the key
its provider issued.

**Says it runs on …** — a platform and device name *supplied by the agent
itself*, marked "unverified". Useful for recognising "my laptop", not proof
of anything.

**Service** — the site or API the agent wants to act at, with the name and
description the service publishes about itself, and its **access mode**:

- *on your identity alone* — with this token the agent can use whatever the
  service gives a recognised person, without asking you again;
- *will ask you separately* — this token only tells the service who the agent
  acts for; the service will come back for specific permissions;
- *normally works with agent identity only* — the agent is asking to be
  recognised as acting for you there.

Some services do not publish a description at all; the screen says so rather
than guessing.

If this is a **new agent** — one that has never acted for you before — a
banner says so first. That is the moment to be suspicious: if you did not
just ask an agent to do something, choose **Don't allow**.

Then the two buttons. **Allow** binds this agent to you (an agent belongs to
one person only), remembers the decision for this agent at this service, and
issues the agent a token that lasts at most an hour, renewable without asking
you again until you revoke. **Don't allow** tells the agent no; nothing is
issued and nothing is remembered.

**Technical details** at the bottom is the raw request, for when you want to
see exactly what was asked.

### The other headings

**"Allow this agent to access this service as you?"** — a *permission*
decision. A service you already allowed the agent at is asking for something
specific, listed under **Asks for**: named permissions with the service's own
description of each, or "no specific permissions". If the agent gave a
reason, it is shown as **Agent's reason** and marked as the agent's own words.
Allowing grants exactly the listed permissions and is remembered; a later ask
for a *subset* will not interrupt you, a superset will.

**"Approve this mission?"** — the agent proposes a *task*: what it will do,
which tools it says it will use ("declared by the agent; nothing enforces
this list"), and which services it will touch. You pick how long the mission
runs — an hour, a day, a week, 30 days, or "no expiry — until you end it here",
which the screen calls least safe for a reason. Approving issues the agent a
token for each listed service, all of them stopping at the time you chose.

**"Is this mission complete?"** — the agent reports it has finished, in its
own words. **Yes, complete** ends the mission for good; **Not yet** leaves it
running.

## Your dashboard

**Agents acting for you** lists every agent bound to you: its identifier,
its provider, what it says it runs on, since when, and a **Revoke** button.
Revoking stops the agent from obtaining new tokens immediately, revokes the
permissions it was granted at every service that received one, and — because
tokens are short — the ones it already holds expire within the hour.

**Missions** shows each mission, active or ended, with the agent's progress
updates and an **End mission** button that revokes everything issued under it.

**What you have allowed** is the list of remembered decisions — which agent,
at which service, what exactly. Revoking an agent withdraws all of its
entries.

**Recent activity** (and **All activity**) is the record: every token
issued, every request denied, every revocation, with the time and the agent.
If a service refused an access that you had allowed, it appears here as the
service's decision, so you know where to look.

**Passkeys** lists your credentials with when each was last used, and lets
you add one.

**Have a code from an agent?** — the box at the bottom, for when an agent
gave you a code without a link.

## What your Person Server never does

- It never sees your calendar, your mail, your files. It tells services *who
  is acting for you*; the service still holds your data and decides what
  that agent may do with it.
- It never gives two services the same name for you. Each service sees a
  pseudonym made just for it, so they cannot compare notes.
- It never lets an agent act for two people, and never lets an agent that
  was revoked come back quietly — a revoked agent has to be approved by you
  again before it can act.
- It never issues anything that lasts longer than an hour without renewal,
  and every renewal stops the moment you revoke.

## If something looks wrong

Choose **Don't allow**, then look at **Activity**. A request you did not
expect is not harmful by itself — nothing is issued until you allow it — but
it is worth knowing which agent asked and from which provider. If you no
longer trust an agent you allowed earlier, **Revoke** it; that is immediate.
