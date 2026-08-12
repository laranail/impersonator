# Impersonation modes

Three modes bound what an impersonated session may do: `read_only`, `limited`, `full`.

The privilege boundary, and the feature that most distinguishes this package. Impersonation
elsewhere is all-or-nothing — the operator becomes the target with every ability the target has.
That is right for debugging and wrong for routine support: an engineer diagnosing a billing
question does not need to be able to place an order.

## The three built in

| Mode | Allows |
|---|---|
| `read_only` | Reads only. Every write is refused at the persistence layer. |
| `limited` | Allowlisted abilities, models, routes or paths. |
| `full` | Everything the target can do. |

```php
Impersonator::enter($customer, mode: 'read_only');
```

```php
'default_mode' => env('IMPERSONATOR_DEFAULT_MODE', 'full'),
```

## The mode cannot change mid-session

Chosen at enter time, stored server-side, and **never read from client input**. There is no
parameter, header or cookie that can alter it. `ImpersonationRequest` is immutable and
`withMode()` returns a new object — the type-level expression of "the only path to another mode is
leave and re-enter", and that path is a fresh authorization check and a fresh audit row.

## Enforcement is not automatic

A mode is enforced by middleware, and the middleware has to be on **your** routes:

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->appendToGroup('web', [
        \Simtabi\Laranail\Impersonator\Laravel\Middleware\EnforceImpersonationMode::class,
        \Simtabi\Laranail\Impersonator\Laravel\Middleware\GuardImpersonationLifetime::class,
    ]);
})
```

Or let the package do it:

```php
'routes' => ['auto_append_to_groups' => ['web']],
```

Registering enforcement only on the package's own routes would enforce nothing — the requests that
need constraining are the application's. A mode that is selectable but not applied reports a
restriction it is not enforcing, which is worse than not offering it at all.

`php artisan laranail::impersonator.doctor` fails when the middleware did not register.

## `read_only`

Blocks writes through `DB::beforeExecuting`, at the persistence layer.

Not by inspecting the HTTP verb, because a verb check is trivially incomplete: a GET route that
writes, a queued job, a Livewire action, an `Artisan::call()`, a raw `DB::table()->update()` —
none of them is a POST. Watching the queries the request actually runs also catches what Eloquent
model events miss, since a query-builder update fires no model events.

The cost is a check per query, which is why this is a mode rather than the default.

A blocked write raises a `ModeViolationBlocked` event and refuses the request. It does not
silently succeed — a read-only session that appears to save is worse than one that refuses.

## `limited`

Four independent allowlists, any combination:

```php
'modes' => [
    'limited' => [
        'abilities' => ['view-invoice', 'download-statement'],
        'models'    => [App\Models\Invoice::class],
        'routes'    => ['billing.*'],
        'paths'     => ['account/*'],
    ],
],
```

Empty means unconstrained on that axis, so `limited` with no configuration behaves like `full` —
configure at least one axis or the mode promises something it does not deliver.

## Custom modes

Register a name and the enforcer that gives it meaning:

```php
use Simtabi\Laranail\Impersonator\Core\Contracts\ModeEnforcer;
use Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

final class BillingOnlyEnforcer implements ModeEnforcer
{
    public function mode(): string
    {
        return 'billing_only';
    }

    public function check(AttemptedAction $action, ImpersonationSession $session): Decision
    {
        return str_starts_with($action->path, 'billing/')
            ? Decision::allow()
            : Decision::deny(Decision::MODE_FORBIDS_WRITE, 'Billing operations only.');
    }

    /**
     * Whether writes should also be checked at the persistence layer, not only per request.
     * Return true and every query the request runs is passed to `check()` as well.
     */
    public function guardsPersistence(): bool
    {
        return false;
    }

    public function describe(): string
    {
        return 'Billing operations only.';
    }
}
```

`check()` receives the session as well as the action, so an enforcer can decide based on who is
being impersonated, the tenant, or anything else on the row — not just the request.

`guardsPersistence()` is what `read_only` returns true for. It is the expensive option (a check per
query) and the thorough one: it catches writes that no HTTP-verb or route inspection would see.

```php
// A service provider's boot()
Impersonator::registerMode(new BillingOnlyEnforcer);
```

The registry pairs each mode with its enforcer, so a mode cannot be registered without one.

With spatie/laravel-permission installed, a new mode also implies a new permission —
`impersonator.mode.billing_only` by default. See [Authorization](authorization.md).

## Per-mode permissions

```php
'authorization' => [
    'permissions' => ['mode' => 'impersonator.mode.%s'],
],
```

This is what pins junior support staff to `read_only` while a senior operator may choose `full`.

Entering requires **both** `impersonator.enter` and the mode's permission. Granting only the
first produces an operator who can impersonate nothing at all while appearing fully configured,
and the error names the *mode* — which sends them asking for the wrong permission. It is the most
common way an install is quietly broken, and the doctor warns about it explicitly.

## Showing the mode

```blade
<x-impersonation-badge />       {{-- renders the mode, or nothing --}}
```

```php
Impersonator::current()?->mode->name;
```

---

[← Docs index](../../README.md#documentation)
