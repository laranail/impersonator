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
- Remember-me is never issued for an impersonated login. A persistent cookie would outlive the
  impersonation and the audit row that bounds it.
- The target is logged in **without firing login events** (`silent_login`). The customer was not
  there: their "new sign-in from a new device" email should not fire, and `last_login_at` should
  not move.
- The operator's own identity is kept server-side, never in a client-readable value.

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
