# Authorization

Who may impersonate whom, in what mode — and the four separate permissions that govern it.

Layered, cheapest-first, and **anything unexpected denies**. A policy that fails open is not a
policy, so an unresolvable target or an unreadable config produces a refusal rather than an
exception somebody might catch and continue past.

## The two policies

```php
'authorization' => ['policy' => null],
```

`null` auto-selects: `RbacPolicy` when a permission package is detected, `BasePolicy` otherwise. Name
a class to take over — extend one of them rather than reimplementing, so the always-on identity rules
cannot be lost by accident.

### Choosing what counts as installed

Detection is a **default-picker only**; an explicit `policy` above always wins. Two ways to change
it, and neither requires touching this package:

```php
// Config: a list of class names probed with class_exists(). First match wins.
'authorization' => ['rbac' => ['detect' => ['Acme\Permissions\PermissionsServiceProvider']]],
```

```php
// Runtime: for a rule a class list cannot express.
Impersonator::detectRbacUsing(fn (): bool => Acme::permissionsEnabled());
```

Detected by **provider class**, not by a trait on the user model: the model may not be loaded this
early, and a provider's presence is the reliable signal a package is wired in rather than merely
sitting in `vendor/`.

**Detection fails closed.** Anything other than a literal `true` selects `BasePolicy` — a truthy
string, a null, or a thrown exception. Reading a broken detector as "yes, this application has
permissions" would hand `RbacPolicy` a permission system it cannot query, and a policy that cannot
query its permissions cannot enforce them. `BasePolicy` still applies every rule in the next section.

The default probes spatie/laravel-permission's provider, because that is the package `RbacPolicy` was
written against — but only as a default. See below: the policy is duck-typed, so nothing about it is
spatie-specific beyond that one name.

## Always active

With or without an RBAC package:

| Rule | Refuses |
|---|---|
| Master switch | Everything, when `enabled` is false |
| Self-impersonation | Impersonating yourself |
| Nesting | Impersonating from inside an impersonation |
| Reason | An enter with no reason, when required |
| Mode registration | An unregistered mode |
| Target allowlist | Any class not in the allowlist — checked *before* the target is loaded |
| Participants resolve | A target or operator that cannot be found |
| Soft deletes | A trashed target, refused *by name* rather than as "not found" |
| Model hooks | `canImpersonate()` / `canBeImpersonated()` returning anything but true |
| Gate | The `impersonate` ability, when the application defines one |
| Concurrency | More than the configured active impersonations |

The allowlist check running before the target loads is the control that stops arbitrary model
injection: naming any Eloquent model through a form field never gets it queried.

## With spatie/laravel-permission

The RBAC layer is **duck-typed** — it calls `hasPermissionTo()`, `hasRole()` and `getRoleNames()`
when the model exposes them. That is spatie's shape but also several other packages', and it means no
hard dependency: this package does not require spatie, not even as a dev dependency, and does not
reference it at compile time. A model with none of those methods inherits the base behaviour.

So pointing `rbac.detect` at a different permission package is genuinely all that is needed — the
policy never names spatie, only the detection default does.

### The four permissions

| Permission | Grants |
|---|---|
| `impersonator.enter` | Impersonating at all |
| `impersonator.mode.%s` | Using a specific mode |
| `impersonator.revoke` | Ending somebody else's impersonation |
| `impersonator.approve` | Deciding a break-glass request |
| `impersonator.audit.view` | Reading the audit trail |

They are genuinely separate. An auditor who may read every impersonation cannot end one. An
operator who may end one does not thereby gain the trail. And **`enter` does not imply
`approve`** — if it did, any two support staff could clear each other's break-glass requests,
which is a rubber stamp with extra steps.

### Entering needs two permissions

`impersonator.enter` **and** the permission for the requested mode. Both. This is what pins junior
staff to `read_only`.

The failure mode is worth stating because it is the most common misconfiguration: an operator
granted only `impersonator.enter` can impersonate nothing, and the refusal names the *mode*, which
sends them asking for the wrong permission. The doctor warns about it.

### Protected roles

```php
'authorization' => ['roles' => ['protected' => ['super-admin']]],
```

Holders can never be impersonated, **by anyone** — including somebody holding every permission. It
is a property of the target, not a comparison, so no amount of privilege gets past it.

### Hierarchy

```php
'authorization' => [
    'roles' => [
        'hierarchy' => null,           // null = built-in level comparison
        'levels' => ['admin' => 80, 'support' => 40, 'user' => 10],
    ],
],
```

The built-in rule requires the operator's highest level to **strictly exceed** the target's, so
peers cannot impersonate one another sideways. Skipped entirely when neither side holds a ranked
role, since a comparison between two unranked users has no meaningful answer.

Supply a closure or invokable class to replace it. Anything other than a clear `true` denies —
this is the one place an application can widen access, so it fails closed.

## Zero permission bleed

While impersonating, effective permissions are the **target's**, narrowed by the mode. The
impersonated session never holds the operator's abilities. Asserted directly in the test suite,
because it is the most consequential property here: the point of impersonation is to see what the
customer sees, and an operator's admin rights leaking through makes the feature both useless and
dangerous.

## Asking before acting

```php
$decision = Impersonator::canImpersonate($customer, 'read_only');

$decision->allowed;   // bool
$decision->code;      // stable machine-readable reason
$decision->reason;    // human-readable
```

This is what the Blade components use to decide whether to render, which is why
`<x-impersonate-button>` needs no `@can` wrapper.

## Gates and the audit policy

The package registers gates for the audit surface, and an `ImpersonationAuditPolicy` covering
`viewAny`, `view`, `export` and `revoke` — all delegating to `AuthorizationPolicy` so there is one
source of truth.

The `impersonate` ability is deliberately **not** defined by the package. It is the application's
override point; defining it here would create a cycle, since the policy consults it.

## Reason codes

Every refusal carries a stable code, so a client can branch on it rather than on message text:

`self_impersonation` · `nested_impersonation` · `target_soft_deleted` ·
`target_not_allowlisted` · `target_opted_out` · `impersonator_not_permitted` ·
`missing_permission` · `missing_mode_permission` · `protected_role` · `hierarchy_violation` ·
`gate_denied` · `reason_required` · `rate_limited` · `concurrency_limit` · `target_busy` ·
`approval_required` · `disabled` · `mode_forbids_write` · `session_terminated`

---

[← Docs index](../../README.md#documentation)
