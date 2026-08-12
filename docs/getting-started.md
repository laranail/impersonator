# Getting started

Impersonate somebody, look around, and leave — in about five lines.

Assumes [installation](installation.md) is done and your user model is allowlisted.

## The shortest possible version

```php
use Simtabi\Laranail\Impersonator\Laravel\Facades\Impersonator;

Impersonator::enter($customer);          // you are now the customer
Impersonator::isImpersonating();         // true
Impersonator::leave();                   // you are yourself again
```

Three things happened that are worth knowing about. The session id was regenerated, so the
impersonated session is not the one you arrived with. An audit row was opened. And no login
event fired for the target, so listeners that send "new sign-in" emails or update
`last_login_at` did not run — the customer was not there.

## Add a button

```blade
<x-impersonate-button :user="$customer" />

{{-- In your layout, once: --}}
<x-impersonation-banner />
```

The button renders nothing when the current operator may not impersonate that account, so it
needs no `@can` wrapper. The banner renders nothing when nobody is impersonating, so it can sit
unconditionally in a layout. See [Blade components](tools/blade-components.md).

## Choose how much access to hand over

Every impersonation carries a **mode**, and the mode is the privilege boundary:

```php
Impersonator::enter($customer, mode: 'read_only');   // GET only
Impersonator::enter($customer, mode: 'limited');     // allowlisted abilities
Impersonator::enter($customer, mode: 'full');        // everything the customer can do
```

`read_only` blocks writes at the persistence layer, not just at the route — a raw
`DB::table(...)->update(...)` is refused too. The mode is chosen when the impersonation starts,
stored server-side, and **cannot be changed mid-session**: escalating means leaving and
re-entering, which is a second audit row and a second authorization check.

To enforce a mode you need the middleware on your application's routes:

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->appendToGroup('web', [
        \Simtabi\Laranail\Impersonator\Laravel\Middleware\EnforceImpersonationMode::class,
        \Simtabi\Laranail\Impersonator\Laravel\Middleware\GuardImpersonationLifetime::class,
    ]);
})
```

Or set `routes.auto_append_to_groups` in the config and the package does it for you. A mode that
is selectable but not enforced reports a restriction it is not applying, which is worse than not
offering it — so this step is not optional. See [Impersonation modes](tools/modes.md).

## Require a reason

```php
// config/impersonator.php
'reason' => ['require' => true],
```

Now an enter without a stated reason is refused, and the reason lands on the audit row. Worth
turning on anywhere impersonation touches customer data — it is the difference between a trail
that records *what* happened and one that records *why*.

## Who is allowed to do this?

Out of the box: anybody who can reach the route. That is fine for a prototype and wrong for
production. Two ways to fix it, and you can use both.

**The model hooks**, for simple rules:

```php
class User extends Authenticatable
{
    public function canImpersonate(): bool
    {
        return $this->is_staff;
    }

    public function canBeImpersonated(): bool
    {
        return ! $this->is_admin;
    }
}
```

**Permissions**, if you have spatie/laravel-permission installed — the RBAC layer activates
automatically:

| Permission | Grants |
|---|---|
| `impersonator.enter` | Impersonating at all |
| `impersonator.mode.read_only` | Using `read_only` |
| `impersonator.mode.full` | Using `full` |
| `impersonator.revoke` | Ending somebody else's impersonation |
| `impersonator.approve` | Deciding a break-glass request |
| `impersonator.audit.view` | Reading the trail |

Note that entering needs **both** `impersonator.enter` and the permission for the mode. Granting
only the first produces an operator who can impersonate nothing while looking correctly
configured — the doctor warns about exactly this. See [Authorization](tools/authorization.md).

## What got recorded

```php
use Simtabi\Laranail\Impersonator\Laravel\Services\AuditService;

$audits = app(AuditService::class);

$page = $audits->paginate(['active' => true]);
$trail = $audits->trail($auditId);
```

Two levels: one row per impersonation, and one row per action taken during it. Neither ever
exposes a credential or a session id. See [The audit trail](tools/audit-trail.md).

## Where to go next

- [Configuration](configuration.md) — the whole surface, block by block
- [Drivers](tools/drivers.md) — session, cross-domain token handoff, per-tenant
- [Auth adapters](tools/auth-adapters.md) — impersonating an API client, not a browser
- [The security model](security.md) — what is guaranteed, and what is not
- [Recipes](../README.md#documentation) — one page per task

---

[← Docs index](../README.md#documentation)
