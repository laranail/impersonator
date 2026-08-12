# Comparison

How this package differs from the alternatives, and when one of them is the better choice.

Written to be useful rather than flattering: if you want a button that logs an admin in as a user
and nothing else, `lab404/laravel-impersonate` is a smaller dependency and you should use it.

## Feature matrix

| | **laranail** | lab404 | octopyid | stechstudio (Filament) | stancl built-in |
|---|---|---|---|---|---|
| Session impersonation | ✓ | ✓ | ✓ | ✓ | ✓ |
| Cross-domain handoff | ✓ | — | — | — | ✓ |
| Multi-tenant driver | ✓ | — | — | — | ✓ |
| Sanctum / Passport / JWT | ✓ | — | — | — | — |
| Multiple user models | ✓ | — | — | partial | — |
| Distinct operator/target guards | ✓ | ✓ | — | ✓ | — |
| Privilege-scoped modes | ✓ | — | — | — | — |
| Read-only enforced at persistence | ✓ | — | — | — | — |
| Session-level audit trail | ✓ | — | — | — | — |
| Action-level audit trail | ✓ | — | — | — | — |
| Tamper-evident audit chain | ✓ | — | — | — | — |
| Audit export (json/csv) | ✓ | — | — | — | — |
| Remote revocation | ✓ | — | — | — | — |
| Max duration | ✓ | — | — | — | — |
| Required reason | ✓ | — | — | — | — |
| Break-glass approval | ✓ | — | — | — | — |
| RBAC permissions + protected roles | ✓ | partial | partial | partial | — |
| Role hierarchy | ✓ | — | — | — | — |
| Concurrency caps | ✓ | — | — | — | — |
| Target notification | ✓ | — | — | — | — |
| Blade components | ✓ | partial | — | Filament only | — |
| REST API | ✓ (opt-in) | — | — | — | — |
| Events | ✓ (14) | ✓ (2) | ✓ | ✓ | — |
| Doctor command | ✓ | — | — | — | — |
| Framework-free domain layer | ✓ | — | — | — | — |

"partial" means the capability exists in a narrower form than the column heading implies.

## The honest summary

**Use lab404** if you want the smallest thing that works. It is mature, widely deployed, and its
API is two methods. If your requirement is genuinely "let an admin log in as a user", the rest of
this page is overhead you do not need.

**Use stechstudio/filament-impersonate** if you live entirely inside Filament and want a row
action that matches the rest of your panel. Its integration is better than anything a
framework-agnostic package can offer inside Filament specifically.

**Use stancl's built-in `UserImpersonation`** if you are already on stancl/tenancy and only need
cross-domain login. It is one class and it ships with the thing you already depend on.

**Use this package** when you need any of: an audit trail somebody will read during an audit, a
privilege boundary narrower than "full access", impersonation of an API client rather than a
browser, more than one impersonatable model, a kill switch, or four-eyes authorisation. Those are
the requirements that make the alternatives fall short, and they tend to arrive together —
usually the first time a compliance questionnaire asks who accessed a customer's account and why.

## Specific differences worth knowing

### Modes are the main one

No other package in this list has a privilege boundary. Impersonation is all-or-nothing: the
operator becomes the target with the target's full abilities. That is often what you want for
debugging and almost never what you want for routine support — a support engineer diagnosing a
billing question does not need to be able to place an order or change an email address.

`read_only` enforces this at the persistence layer via `DB::beforeExecuting`, not by inspecting
the HTTP verb, so a GET route that writes, a queued job, a Livewire action and a raw
query-builder call are all caught.

### Two audit levels, not one

Most alternatives record nothing, or fire an event and leave persistence to you. Here there is one
row per impersonation and one row per action taken during it, with causer attribution, optional
HMAC tamper evidence, export in JSON or CSV, and retention through `MassPrunable`.

### The token handoff is hardened differently to stancl's

stancl's `UserImpersonation` stores its tokens **unhashed**, its single-use check is not atomic,
and it authenticates with `loginUsingId()` — which fires login events for a user who is not there.

This package was deliberately *not* built as a wrapper around it. The token driver reuses none of
that machinery: tokens are 40 bytes of `random_bytes` stored as SHA-256 digests, looked up by
digest, redeemed by a single conditional `UPDATE` whose affected-row count arbitrates between
concurrent callers, and the target is logged in without firing events. The tenancy driver
integrates with stancl for *tenant resolution*, which is what stancl is genuinely good at.

### Adapters, not just sessions

The four auth adapters are why this package can impersonate an API client. Handing a mobile
client a Sanctum token that is scoped to `read_only` and expires in ten minutes is a
configuration here; elsewhere it is a fork.

### The layered domain

`src/Core` imports no `Illuminate` code, enforced by an architecture test. The practical payoff
is not portability — it is that the whole authorization decision is testable without a request,
a session or a container, which is the only reason the suite can carry as many refusal tests as
it does.

## Migrating from lab404

The concepts map closely, so the change is mostly mechanical:

| lab404 | Here |
|---|---|
| `$user->impersonate($other)` | `$user->impersonate($other)` (same trait method) |
| `$user->leaveImpersonation()` | `$user->leaveImpersonation()` |
| `app('impersonate')->isImpersonating()` | `Impersonator::isImpersonating()` |
| `impersonate.take` / `impersonate.leave` routes | `impersonator/enter` / `impersonator/leave` |
| `canImpersonate()` / `canBeImpersonated()` | identical hooks |
| `$impersonate->getSessionKey()` | server-side only; not client-readable |

Remove lab404 before adding this one, or at least read the doctor's conflict warning: both
register routes and session state, and leaving through one does not end an impersonation started
by the other — which produces an audit trail that disagrees with itself.

---

[← Docs index](../README.md#documentation)
