# Security model

What is guaranteed, how each guarantee is implemented, and what is explicitly not promised.

Impersonation is a privilege-escalation feature. Treating it as a convenience is how it becomes
an incident, so this page is worth reading before the configuration reference.

## Handoff tokens

Used by the `token` and `tenancy` drivers for cross-domain and per-tenant handoffs.

| Property | How |
|---|---|
| Unguessable | 40 bytes from `random_bytes`, base64url-encoded; 32-byte floor enforced in code |
| Never stored in the clear | Only a SHA-256 digest is written; lookups are *by* the digest |
| Single-use | Redemption is one `UPDATE ... WHERE consumed_at IS NULL`; the affected-row count arbitrates |
| Short-lived | 60 second default TTL |
| Throttled | The accept route carries its own rate limiter |
| Re-authorized | The full policy runs again at redemption, not only at issue |
| Never logged | The plaintext appears in exactly one place: the accept URL returned to the caller |

A plain SHA-256 digest is correct here rather than bcrypt: the value is already 40 bytes of CSPRNG
output, so there is nothing to brute-force and no reason to pay a password hash on every
redemption.

**Every rejection looks identical to the client.** Unknown, expired, spent and revoked are
distinguished only in the audit log, because telling somebody probing the accept route that a
token merely *expired* tells them the token was real.

**A refused redemption still burns the token.** A token that survived a failed attempt could be
retried until the window happened to open, and the operator can always be issued a fresh one.

## Sessions

- The session id is regenerated on **enter and on leave**. Fixation in either direction would let
  a session captured before the switch be replayed after it.
- **The session's contents are cleared too, not just its id.** Rotating the id keeps the session's
  attributes, so without a flush the operator's cart, half-finished form or flashed data travels
  into the impersonated session — and whatever the target accumulates travels back out on leave.
  That is a cross-account data leak in both directions, and it is the bug most implementations in
  this space still carry. Configurable via `session.flush_on_switch`, on by default. The one
  exception is deliberate: when the operator sits on a *different* guard, their own auth key
  survives the flush, because they were never displaced and must stay logged in.
- A **fresh CSRF token** is minted on each switch, so a token issued at one privilege level is not
  still valid at another.
- Remember-me is never issued for an impersonated login. A persistent cookie would outlive the
  impersonation and the audit row that bounds it.
- **Leaving never calls `Auth::logout()` on the target.** Laravel's `logout()` rotates the user's
  `remember_token`, which would log the real customer out of every device they own — and forget a
  recaller cookie they set weeks ago on a phone this package has never seen — as a side effect of a
  support engineer finishing their work. Only the guard's session key is forgotten, plus the cached
  user on that one guard.
- The target is logged in **without firing login events** (`silent_login`). The customer was not
  there: their "new sign-in from a new device" email should not fire, and `last_login_at` should
  not move.
- The operator's own identity is kept server-side, never in a client-readable value.

### What the session driver changes

`SESSION_DRIVER=cookie` keeps no server-side record, so a revoked session cannot be destroyed out
of band — a retained copy of the cookie stays valid until the middleware sees it on the next
request. The doctor command reports this rather than letting you assume the stronger guarantee.

## Handoff tokens in URLs

A handoff token has to ride in a URL: the whole point is a link an operator follows on another host.
A URL leaks where a request body does not, and the significant channel is **logs**, not the
`Referer` header — nginx's default `combined` format writes the full request line to disk, and every
proxy, CDN and log aggregator in between keeps its own copy for its own retention period.

Laravel's own tooling is the sharpest edge. Telescope's request watcher records the URI, and the
scaffolded production filter records failed requests — so a 419 or a 500 on the accept route writes
the full token URL into `telescope_entries`, which is exactly the case where the token was *not*
consumed and may still be live. `hideRequestParameters()` masks the payload, never the URI.

What bounds the exposure here: a 60-second TTL, a single-use atomic claim, rejections that are
indistinguishable to the client, and `Referrer-Policy: no-referrer` plus `Cache-Control: no-store`
on the accept response so the URL does not travel onward as a referrer or sit in a shared cache.

If your threat model includes your own log retention, exclude the accept path from request logging
at the web server, and from Telescope with `Telescope::filter()`.

## Impersonation modes

Three built in — `read_only`, `limited`, `full` — plus your own via `ModeEnforcer`.

The mode is **chosen at enter time, stored server-side, and never read from client input**. There
is no request parameter, header or cookie that can change it. `ImpersonationRequest` is
immutable and `withMode()` returns a new object, which is the type-level expression of "the only
path to another mode is leave and re-enter" — and that path is a second authorization check and a
second audit row.

`read_only` blocks writes via `DB::beforeExecuting`, at the persistence layer. A verb check would
miss a GET route that writes, a queued job, a Livewire action and every raw query-builder call;
Eloquent model events would miss the query-builder calls too.

## Authorization

Layered, cheapest-first, and **anything unexpected denies**. A policy that fails open is not a
policy, so an unresolvable target or an unreadable config produces a refusal rather than an
exception somebody might catch and continue past.

Always active, with or without an RBAC package:

- No self-impersonation.
- No nesting (unless explicitly enabled).
- The target class must be in the allowlist — checked *before* the target is loaded, so naming an
  arbitrary Eloquent model never gets it queried.
- Soft-deleted targets are refused by default, and refused *by name* rather than reported as
  "not found", so an operator is not sent looking for a missing record.
- The `canImpersonate()` / `canBeImpersonated()` model hooks.
- The `impersonate` gate ability, when the application defines one.
- Concurrency caps, enforced inside a locked transaction.

With spatie/laravel-permission installed, additionally:

- `impersonator.enter` **and** the per-mode permission. Both, not either.
- Protected roles can never be impersonated, by anyone — it is a property of the target, not a
  comparison, so no amount of privilege gets past it.
- A hierarchy rule: the operator's highest role level must strictly exceed the target's, so peers
  cannot impersonate each other sideways.

Entering, revoking, approving and reading the trail are **four separate permissions**. An auditor
who can read every impersonation cannot end one; an operator who can end one does not thereby
gain the trail; and nobody gets to approve their own request.

## Timed impersonation

Every impersonation carries a deadline, defaulting to **ten minutes**, enforced on the target
session's next request by the lifetime middleware. It is checked against both the durable audit row
and the session's own copy, so neither a stale cache nor a hand-edited session extends it.

Extension moves that deadline in place, and it is the only non-terminal mutation the audit store
permits. Four properties hold:

- **Monotonic.** The expiry may only move forward. Nothing reachable from the store's contract can
  shorten a live impersonation or rewrite its opening facts.
- **Bounded twice.** A count (`max`) and a total elapsed duration (`max_total_duration`), stricter
  wins. Both matter: a count bounds no amount of time when the window is configurable, and a total
  alone never asks the operator to re-justify. Setting both to null makes the deadline advisory, and
  the doctor says so.
- **Atomic.** The caps are evaluated against the row *inside* a locked transaction, not before one.
  Two concurrent extensions — an operator double-clicking is the ordinary case — would otherwise both
  read the same remaining allowance and both spend it.
- **It cannot outrun a revocation.** Between an administrator marking a row and the target session's
  next request, that impersonation is both active and revoked. Extending inside that window is
  refused, or an operator could buy time against their own kill switch.

Permission is **re-checked** on every extension rather than inherited from the fact that a session
exists. Extending asks for more access, unlike leaving, which only de-escalates — so an operator
whose role was withdrawn mid-session can finish what they are doing and leave, but cannot buy another
window.

**The audit hash chain is unaffected**, because `expires_at`, `extensions` and `extended_at` are not
among the chained facts — the chain covers the immutable opening facts only. That is what makes an
extendable window acceptable in an audited system: moving the deadline can neither forge tamper
evidence nor break it. The count and the last extension time are recorded on the row, so a trail
showing three extensions answers a question that a single row reading "fifty minutes" cannot.

## Operator-side controls

Four controls that bound what an operator can do, all **off by default** — each can refuse an
impersonation an installation expects to work, so switching one on is a decision.

| Control | Config | What it stops |
|---|---|---|
| Step-up re-auth | `authorization.step_up.require` | A stolen session cookie reaching every account |
| Idle timeout | `limits.max_idle` | A tab abandoned inside a customer's account |
| Per-request re-authorization | `authorization.recheck_each_request` | A revoked role leaving live sessions running |
| Target eligibility | `targets.eligibility` | Impersonating a blocked or internal account |

**Step-up** is the strongest of them and the one with a citable precedent: it is what GitLab's Admin
Mode exists to provide, and ASVS 7.5.3 treats entering impersonation as a highly sensitive operation.
It reads the timestamp Laravel's own `password.confirm` flow writes, so it needs a host-side route —
which is why it is off by default. Turning it on without that flow refuses everything.

It refuses on an **absent** timestamp as well as a stale one. Absent is the more important half: an
install that forgot the flow produces exactly that case, and treating "never confirmed" as passing
would make the control decorative.

**Idle timeout** is separate from `max_duration`, which is absolute. An impersonation abandoned
mid-session is the row that turns up in an audit with no explanation, and an absolute cap alone leaves
it open for the whole window. Tracked in the session, so it costs no query. An absent stamp is treated
as "first request", not as infinitely old — otherwise every impersonation would die on its second
request.

**Per-request re-authorization** costs a permission lookup per request, which on an RBAC package backed
by the database is not free. It is memoised per request. Without it, revoking an operator's role leaves
their impersonations running until the duration cap — so the withdrawal that mattered most is the one
that takes effect last.

**Target eligibility** is where an application expresses what this package cannot know: blocked,
password-expired, internal and bot accounts are all states GitLab refuses and this package has no way
to detect. Like every extension point here it **fails closed** on anything but a literal `true`,
including a thrown exception.

## Long-running servers

Octane, queue workers and `artisan serve --workers` keep the container alive across requests, so a
singleton that remembers one request answers for the next. In an impersonation package that is not
tidiness: `stechstudio/filament-impersonate` #146 is *"impersonation targets the wrong user under
Octane/Swoole"*, and wrong-user is data exposure.

All seventeen singletons were audited for mutable state rather than assumed about. Exactly two hold
request state and are reset on `RequestReceived` **and** `RequestTerminated` — both, because a request
that dies hard never reaches the second:

- **`PersistenceGuard`**, armed for one request with one impersonation. The middleware disarms it in a
  `finally`; this is the belt to that braces.
- **`FailureReport`**, which accumulates degraded state with no expiry. One transient blip otherwise
  makes `isHealthy()` false for the life of the worker, so the doctor and every health probe report
  degraded forever after a single failure.

Everything else holds either nothing (`Settings`, `MessageCatalog`, `RedirectGuard`,
`IdentityResolver` and `SessionState` are `readonly`) or **boot-time registrations that must survive** —
the manager's driver factories, `ReviewerDirectory`'s eligibility closure, `ModeRegistry`'s enforcers.
Resetting those would delete a custom driver an application registered, which is a worse bug than the
one being fixed. `TargetRegistry`'s config memo is deliberately kept warm.

A doctor check fails when Octane is installed and the resets are not registered.

## Tamper evidence is not tamper resistance

The HMAC chain over the audit trail detects alteration: change or delete a row and `verify-audit`
reports a break at that point. What it cannot do is *prevent* the alteration, because the application's
own database user can write that table.

ASVS 16.4.2 and 16.4.3 ask for logs that cannot be modified and that are shipped off-box, and an audit
table alone meets neither. Closing the gap needs a sink outside the application's reach:

```php
'logging' => ['audit_channel' => env('IMPERSONATOR_AUDIT_LOG_CHANNEL')],
```

Every tamper-relevant line — started, ended, extended, revoked, expired, mode violations, approval
decisions — is written there as well as to the ordinary channel. Point it at a syslog, a SIEM, or
anything append-only, and the two records have to be altered in concert rather than in one place.

Also worth knowing: the audit hash key must live **outside** the database it protects. A key stored
beside the rows it signs lets whoever alters a row recompute the chain, which is why the provider
refuses to boot with tamper evidence on and no key configured.

See [Events](tools/events.md#a-separable-audit-sink).

## Rate limits during impersonation

A rate limit exists to bound a *caller*. During an impersonation the caller is the operator and
`$request->user()` is the target, so any limit keyed on the authenticated user charges the wrong
account. That is worse than an accounting error:

- **The customer is throttled by the support they asked for.** An operator working through an
  account spends that customer's quota, and the customer starts seeing 429s.
- **It is a denial-of-service primitive.** One authorised operator can deliberately exhaust a chosen
  customer's limit, and the request log shows the customer doing it to themselves.

The package's own three limiters resolve the operator first and fall back to the authenticated user,
so `impersonator-enter` and `impersonator-api` cannot be spent against a target. (`impersonator-accept`
stays keyed on the IP — the caller redeeming a handoff has no session yet.)

**Your application's limits are not covered by that**, because the package does not replace the
framework's `throttle` for you; deciding that for an application is not its call. Two integrations are
provided — the `impersonator.throttle` middleware and `Impersonator::rateLimitKey()` — both shown in
[Rate limiting](configuration.md#rate-limiting).

## Sessions and the password-hash sentinel

Laravel's `auth.session` middleware (`AuthenticateSession`) stores a hash of the authenticated user's
password in the session and compares it on every request; a mismatch means the password changed
elsewhere, so it flushes the session and logs the user out. Switching the authenticated user is
indistinguishable from that, so an unhandled switch logs the **operator** out at the next request —
inside the customer's account, with no explanation.

The package re-syncs the sentinel on both the switch and the restore, for the guard actually in use
rather than the default one, mirroring the framework's own `hashPasswordForCookie()` pass. That holds
whether or not `session.flush_on_switch` is enabled: the flush happens to mask the problem by clearing
the stale value, but it is a documented opt-out, so the fix does not depend on it.

## Zero permission bleed

While impersonating, effective permissions are the **target's**, narrowed further by the mode.
The impersonated session never holds the operator's abilities. This is asserted directly in the
test suite rather than assumed, because it is the single most consequential property here — the
whole point of impersonation is to see what the customer sees, and an operator's admin rights
leaking through makes the feature both useless and dangerous.

## Validation and injection

- Form Requests on every endpoint, HTML and API alike, sharing one set of rules — the API
  request classes extend the HTML ones so two copies cannot drift.
- `target_type` must be a registered morph alias. This is the control that stops arbitrary class
  injection.
- `guard` must exist in `config('auth.guards')`.
- `redirect_to` is validated against an allowlist; relative paths only unless a host is
  explicitly permitted. An open redirect on an impersonation entry point is a
  credential-phishing primitive.
- Rate limits on entering, redeeming and the API. Entering is limited **per operator rather than
  per address**: the risk is one authorised person enumerating accounts, and they do it from a
  single address.

## Remote revocation

An administrator holding `impersonator.revoke` can end any impersonation.

For a token credential the invalidation is immediate. For a session it depends on the store:
with `database`, `redis` or `file` the session is destroyed out of band through
`SessionHandlerInterface::destroy()` and the effect is immediate; with `cookie` or `array` there
is nothing to reach into, so the revocation is *recorded* and the middleware ends the session on
its next request.

The API says which of the two happened in `meta.terminated` rather than implying the stronger
guarantee. The doctor command warns when the configured session driver cannot support immediate
termination.

Note that revocation deliberately does **not** consult the master switch. Turning impersonation
off during an incident must not also remove the ability to kill the sessions already running.

## What is written where

Never in a log, a response, a listing, an export, or the `about` output:

- token plaintext
- credential secrets
- credential hashes — a digest is still a verifier, so a holder can confirm a guessed token
  against it
- session ids
- the audit hash key
- approval fingerprints

The only response that ever carries a secret is `POST /impersonations`, which returns the accept
URL or the issued credential exactly once.

Request payloads are **not** recorded in the action trail by default. Turning
`trail.record_payloads` on runs every payload through recursive redaction first — but redaction
is a filter, not a guarantee, which is precisely why it is off.

## Reporting a vulnerability

Do not open a public issue. Email `opensource@simtabi.com` — see
[SECURITY.md](../SECURITY.md).

---

[← Docs index](../README.md#documentation)
