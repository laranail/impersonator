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

Two layers, both on by default:

```php
'modes' => [
    'read_only' => [
        // Unsafe methods are refused.
        'allowed_methods' => ['GET', 'HEAD', 'OPTIONS'],

        // The escape hatch that keeps an operator from being trapped. Matched on the
        // route name *and* the path, so an application that renamed its logout route
        // does not thereby lock people in.
        'allowed_routes' => ['impersonator.leave', 'logout'],

        // The persistence-layer net. On by default.
        'prevent_writes' => true,
    ],
],
```

The method check alone is trivially incomplete: a GET route that writes, a queued job, a Livewire
action, an `Artisan::call()`, a raw `DB::table()->update()` — none of them is a POST. So
`prevent_writes` hooks `DB::beforeExecuting` and inspects the queries the request actually runs,
which also catches what Eloquent model events miss, since a query-builder update fires none.

It ships **on**, because a mode named read_only that permits a write behind a GET route is not
read-only, and that guarantee is the entire reason to offer the mode. The usual objection to a
persistence guard — that aborting mid-request can strand earlier writes — does not apply here:
every write is denied, so the first one aborts and there is nothing half-done behind it. (That
objection is real for `limited`, which is why its guard switches on only when `deny_models` is
configured.)

### Livewire

Every Livewire action POSTs to **one** endpoint (`livewire/update`), with the component and method in
the payload. So `deny_routes`, `deny_paths` and `allowed_methods` see one route, one path and one HTTP
method for every action in the application: a rule naming `password.update` would match nothing, and a
rule broad enough to match would block everything.

`deny_livewire` closes that by reading what the payload actually says:

```php
'modes' => ['limited' => ['deny_livewire' => [
    'ProfileForm::updatePassword',   // one action
    'BillingPanel::*',               // a whole component
    '*::destroy',                    // a method wherever it appears
]]],
```

Same `Str::is` matching as `deny_routes`, against the qualified `Component::method`, the bare component
and the bare method. Batched requests are checked call by call, so a denied action cannot ride along
behind an allowed one.

| Axis | Under Livewire |
|---|---|
| `deny_livewire` | Works — reads the component and method from the payload |
| `deny_models` | Works — enforced on the query, not the route |
| `deny_abilities` | Works — enforced at the Gate |
| `deny_routes` / `deny_paths` | Inert; use `deny_livewire` instead |
| `allowed_methods` | Inert; everything is a POST |

Empty by default, like `deny_models`: the component names are yours and this package cannot guess them.
The payload is not parsed at all until you configure something here.

Both Livewire 2 (`livewire/message/{component}` with `callMethod` updates) and Livewire 3
(`components[].snapshot` with `calls[]`) are read, because both are in the wild and handling only the
newer one would silently enforce nothing on the older.

> **What this coverage does and does not prove.** Livewire is deliberately not a dependency of this
> package, so the tests drive the documented payload shapes directly rather than a live Livewire. They
> prove the parsing and the matching; they do not prove that a given Livewire release still sends that
> shape. An unparseable payload makes the axis *not match* — never allow by fiat — so the other axes
> still apply, and `read_only` is unaffected either way because its guard is at the persistence layer
> and does not care how the request arrived.

The cost is a check per query. Turn it off only for a specific incompatibility, and know that
`read_only` then bounds HTTP methods alone:

```php
'prevent_writes' => env('IMPERSONATOR_READ_ONLY_PREVENT_WRITES', false),
```

`allowed_routes` is a safety property rather than a convenience. A mode that could trap an operator
inside a customer's account would be worse than no mode at all, so leaving and logging out stay
reachable no matter what else is denied.

A blocked write raises a `ModeViolationBlocked` event and refuses the request. It does not
silently succeed — a read-only session that appears to save is worse than one that refuses.

## `limited`

Writes are allowed **except** what you deny. Four independent deny-lists, any combination:

```php
'modes' => [
    'limited' => [
        'deny_routes' => [
            'password.update',
            'password.confirm',
            'profile.destroy',
            'two-factor.enable',
            'two-factor.disable',
        ],
        'deny_paths' => [
            'billing/*',
            'settings/password',
            'settings/two-factor*',
        ],
        'deny_abilities' => [
            'delete-account',
            'update-password',
            'manage-billing',
        ],
        'deny_models' => [
            // App\Models\PaymentMethod::class,
        ],
    ],
],
```

A deny-list rather than an allow-list, and the choice is deliberate: an allow-list of routes has to
be re-audited every time the application grows a route, and the one somebody forgets to add is the
one that gets blocked in production. Denying the account-takeover paths instead means a new feature
is reachable by default and the dangerous set stays small and reviewable.

The shipped defaults are **not empty** — they already cover password changes, two-factor toggles,
account deletion and billing, which are the paths a support session should never reach. Widen them
to match your own application; the same operation is often reachable by more than one route, so deny
on the axis that actually identifies it.

`deny_models` is the only axis that needs the persistence guard, because a route pattern cannot tell
you which model a controller is about to write. Configuring it turns that guard on automatically;
leaving it empty keeps `limited` to a per-request check.

Safe methods are always allowed. This mode narrows what can be *changed*, not what can be read —
so a deny-listed area is still viewable, which is usually the point of impersonating in the first
place.

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
