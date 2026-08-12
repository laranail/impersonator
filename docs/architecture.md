# Architecture

Two layers, two orthogonal axes, and one composition root — plus the reasoning behind each.

## The layers

```
src/Core/      pure PHP: contracts, value objects, enums, events, domain support
src/Laravel/   the bridge: drivers, adapters, stores, middleware, HTTP, Blade, commands
```

`src/Core` imports no `Illuminate` code at all and calls no framework helper, and two architecture
tests assert this on every commit:

```php
arch()->expect('Simtabi\Laranail\Impersonator\Core')->not->toUse('Illuminate');
arch()->expect('Simtabi\Laranail\Impersonator\Core')->not->toUse(['app', 'auth', 'config', …]);
```

It imports `psr/log`, `psr/clock`, `psr/event-dispatcher`, and — for enum labels only —
`laranail/enumerator`. A third test pins that list closed, so adding anything else to Core is a
decision somebody makes rather than an import somebody happens to write.

> **What this does not claim.** `laranail/enumerator`'s own Composer requirements include six
> `illuminate/*` packages, so Core's *dependency tree* is not framework-free even though its *code*
> is: a Symfony application consuming Core would pull Illuminate in through Composer. What does hold
> is that the code still runs without a booted framework — every Laravel touchpoint in enumerator's
> traits is `function_exists()`-guarded, the one that is not (`class_basename()` in
> `translationSlug()`) is overridden on each of our enums, and a unit test with no application booted
> asserts every label still resolves.

### Why bother?

Not portability for its own sake — see the caveat above; the dependency tree gave that up. The
payoff is that **the entire authorization decision is testable without a framework**. `BasePolicy`
and `RbacPolicy` take value objects in and return a `Decision`; there is no request, no session,
no container, and no database in the way. That means the rules that decide who may impersonate
whom can be exercised exhaustively and cheaply, which is the only reason a package like this can
carry as many refusal tests as it does.

The second payoff is that the boundary makes leakage visible. A framework concern that drifts
into the domain logic breaks the build rather than quietly making the policy harder to reason
about.

### The ports

Everything the domain needs from the outside world is one of these, all in
`Core/Contracts`:

| Contract | Answers |
|---|---|
| `AuthorizationPolicy` | May this impersonation happen? |
| `ImpersonationDriver` | How does an impersonation begin and end? |
| `AuthAdapter` | How is the target actually authenticated? |
| `AuditStore` | Where do impersonation records live? |
| `TrailStore` | Where do per-action records live? |
| `TokenRepository` | Where do single-use handoff tokens live? |
| `ApprovalStore` | Where do break-glass approvals live? |
| `ModeEnforcer` | Is this action permitted in this mode? |
| `FailureReporter` | Where does a reported failure go? |

Every one has an Eloquent or Laravel implementation in `src/Laravel`, and every one can be
replaced through a container binding without touching the package.

## The two axes

The design decision that shapes the public surface: **how an impersonation is established** and
**how the target is authenticated** are independent, and the manager composes them.

|  | `session` adapter | `sanctum` | `passport` | `jwt` |
|---|---|---|---|---|
| **`session` driver** | the common case | — | — | — |
| **`token` driver** | cross-domain browser handoff | issue a token to a client | ditto | ditto |
| **`tenancy` driver** | per-tenant browser | per-tenant API | ditto | ditto |

Collapsing these into one dimension — a "sanctum driver", a "cross-domain driver" — is the design
most packages in this space chose, and it is why they cannot do the combinations. Keeping them
apart costs one indirection and makes "hand an API client a short-lived token that is scoped to
read-only and expires in ten minutes" a configuration rather than a fork.

## Actions, services, manager

```
ImpersonationManager     composition root: registries, resolution, extension points
    ↓
ImpersonationService     orchestration: build a request, pick a driver, delegate
ApprovalService          orchestration: the break-glass queue
AuditService             orchestration: the read path over the trail
    ↓
EnterImpersonation       one action, one unit of work
LeaveImpersonation
RevokeImpersonation
RequestApproval
DecideApproval
```

The actions are where the rules live, and there is exactly one of each. Every entry point — the
HTTP controllers, the REST API, the `Impersonates` trait, the console `enter` command — goes
through the same action, which is what makes it structurally impossible for a second entry point
to grow its own slightly-different copy of the authorization stack. That has been the failure
mode in every impersonation package that added an API after the fact.

The manager is deliberately *not* the service. It resolves drivers, adapters, modes and target
types and owns `extend()`, `extendAdapter()`, `registerMode()` and `registerTarget()`. Keeping it
separate means the doctor command can ask "which driver would you use" without any risk of
performing an impersonation.

## Why the audit row opens before authentication

All three drivers write the audit row *first*, then authenticate. It reads backwards and it is
deliberate: if authentication fails halfway — the adapter throws, the guard rejects, the process
dies — the attempt is still on record. A row written after a successful login records only the
impersonations that worked, which is the opposite of what an audit trail is for.

## Why modes are enforced at the persistence layer

`read_only` hooks `DB::beforeExecuting` rather than only inspecting the HTTP verb. A verb check
is trivially incomplete: a `GET` route that queues a job, a Livewire action, an
`Artisan::call()`, a raw `DB::update()` — none of them are a POST. Watching the queries the
request actually runs catches the writes that Eloquent events also miss, because a query-builder
update fires no model events at all.

The cost is that it is a per-query check. That is why it is a mode rather than the default.

## Why leaving needs no permission

`LeaveImpersonation` consults no policy. Leaving only ever de-escalates, and an operator whose
access was revoked mid-session must still be able to stop being somebody else. A permission check
on the exit is a design that can trap a person inside a customer's account.

## Failure handling

Every operation the package performs is classified `Critical` or `Degradable`, and the
classification is the reviewable decision:

- **Critical** — drivers and adapters, the middleware, the gates, exception rendering. A failure
  here means nothing works, or a control is silently not enforcing. It throws.
- **Degradable** — routes, views, Blade components, listeners, notifications, the trail. A
  failure is reported to `FailureReport` and execution continues.

A mail server that is down must not prevent a support engineer helping a customer, and it must
certainly not prevent a *revocation*. But a degraded operation that nobody can observe is just a
bug with good manners, so `FailureReport` is queryable — the doctor command reads it, and CI
asserts it is healthy after a normal boot. There is no environment branching anywhere: what
crashes in development crashes in production, which is the only way the test suite exercises what
actually ships.

## Why tamper evidence is a keyed chain

Each audit row's digest covers the previous row's digest plus the immutable opening facts of this
one — who, whom, which mode, when it started. It deliberately does **not** cover the mutable
columns, because `ended_at` and `revoked_at` are written after the digest and a chain over them
would break on every normal close.

The key lives in config, outside the database, and that is the whole mechanism: a chain whose key
is stored alongside the rows protects nothing, since anybody who can alter a row can recompute
the digest. The chain proves *tampering happened*, not who did it, and it cannot prevent it. That
is the honest claim, and it is why `verify-audit` reports the first row where the chain breaks
and treats everything after it as suspect.

## What this does not do

Worth stating plainly, because these are the questions the design answers with "no":

- **The impersonated session never holds the operator's permissions.** Effective permissions are
  the target's, narrowed by the mode. Anything else is privilege escalation with a nicer name.
- **Nesting is refused by default.** Once an impersonated session can reach a third account, the
  trail stops describing who actually acted.
- **A mode cannot be escalated mid-session.** `ImpersonationRequest` is immutable and a different
  mode is a different request.
- **A revocation cannot always be immediate.** With a server-side session store it is; with
  `cookie` or `array` there is nothing to destroy from outside, so it is recorded and the session
  ends on its next request. The package says which, rather than implying the stronger guarantee.

---

[← Docs index](../README.md#documentation)
