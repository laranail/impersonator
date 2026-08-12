# Configuration

Every block in `config/impersonator.php`, and what each one changes.

Publish it with `php artisan vendor:publish --tag=impersonator-config`. The defaults are chosen so
that an unconfigured install is safe rather than convenient: the API is off, tamper evidence is
off, notifications are off, approvals are not required, and nothing can be impersonated until you
name a model.

## The one setting you must change

```php
'targets' => [
    'allowlist' => [
        'user' => App\Models\User::class,
    ],
    'allow_soft_deleted' => false,
],
```

An allowlist, not a shortcut. A request naming any other class is refused before the target is
loaded. An empty allowlist refuses everything. Multiple models, each with its own guard and
display attribute, are supported — see [Impersonatable targets](tools/targets.md).

## Master switch

```php
'enabled' => env('IMPERSONATOR_ENABLED', true),
```

False refuses every enter. **Revocation still works**, deliberately: turning the feature off
during an incident must not also remove the ability to kill the sessions already running.

## Driver and adapter

```php
'driver'  => env('IMPERSONATOR_DRIVER', 'session'),
'adapter' => env('IMPERSONATOR_ADAPTER', 'session'),
```

Two independent axes. The driver decides *how an impersonation is established*; the adapter
decides *how the target is authenticated*. See [Drivers](tools/drivers.md) and
[Auth adapters](tools/auth-adapters.md).

```php
'adapters' => [
    'sanctum'  => ['ability' => 'impersonated', 'expires_after' => 15],
    'passport' => ['scope'   => 'impersonated', 'expires_after' => 15],
    'jwt'      => ['ttl' => 15],
],
```

`expires_after` (and `ttl` for JWT) is in minutes. The single `ability` / `scope` is deliberate: an
impersonation token is narrowed to one named capability rather than inheriting `*`, so a resource
server can recognise it without knowing this package exists. Passport never issues a refresh token,
and that is not configurable — it would let an impersonation renew itself past its own audit row.

## Guards

```php
'guards' => [
    'impersonator' => 'web',
    'target'       => 'web',
],
```

Both must exist in `config/auth.php`. They can differ — a staff guard impersonating onto a
customer guard is a normal arrangement, and each allowlisted target type may override the target
guard.

## Modes

```php
'default_mode' => env('IMPERSONATOR_DEFAULT_MODE', 'full'),

'modes' => [
    'read_only' => [
        'allowed_methods' => ['GET', 'HEAD', 'OPTIONS'],
        'allowed_routes'  => ['impersonator.leave', 'logout'],
        'prevent_writes'  => true,
    ],
    'limited' => [
        'deny_routes'    => ['password.update', 'profile.destroy', '...'],
        'deny_paths'     => ['billing/*', 'settings/password', '...'],
        'deny_abilities' => ['delete-account', 'update-password', '...'],
        'deny_models'    => [],
        'deny_livewire'  => [],
    ],
    'full' => [],
],
```

The privilege boundary. `read_only` refuses unsafe methods and — with `prevent_writes`, which is on
by default — every write at the persistence layer. `limited` allows writes *except* the deny-listed
routes, paths, abilities and models, and ships with the account-takeover paths already denied.
`full` is everything the target can do.

`deny_livewire` exists because the route and path axes **cannot see** a Livewire action — every one of
them POSTs to a single endpoint with the component and method in the payload. See
[Livewire](tools/modes.md#livewire).

`allowed_routes` is a safety property, not a convenience: leaving and logging out stay reachable
whatever else is denied, because a mode that could trap an operator inside a customer's account
would be worse than no mode at all.

Registering your own mode means registering a `ModeEnforcer` with it — a mode that is selectable
but not enforced reports a restriction it is not applying. See
[Impersonation modes](tools/modes.md).

## Polymorphic columns

```php
'morphs' => [
    'key_type'     => env('IMPERSONATOR_MORPH_KEY_TYPE', 'string'),
    'register_map' => env('IMPERSONATOR_REGISTER_MORPH_MAP', true),
    'require_map'  => env('IMPERSONATOR_REQUIRE_MORPH_MAP', false),
],
```

Every participant is stored as a morph pair — see
[Polymorphic columns](tools/audit-trail.md#polymorphic-columns) for the column names.

`key_type` governs the `*_id` half, and is read **only when the migration runs**:

| Value | Column | Requires |
|---|---|---|
| `string` | `string` | Nothing — mixed key types in one table |
| `numeric` | `unsignedBigInteger` | Every impersonatable model uses integer keys |
| `uuid` | `char(36)` | Every impersonatable model uses UUIDs |
| `ulid` | `char(26)` | Every impersonatable model uses ULIDs |

`string` is the default rather than `unsignedBigInteger` — which is what Laravel's own `morphs()`
would give — because that would make the table unable to hold a UUID-keyed model, and holding
several differently-keyed models in one trail is the point of a multi-model allowlist. Changing this
after migrating needs a migration of your own; the package will not silently rewrite columns.

`register_map` publishes `targets.allowlist` into Laravel's own morph map at boot, and is **on** because
without it the package's `morphTo()` relations cannot resolve: the column holds `user`, and Eloquent with
no entry for it tries to instantiate a class named `user`. An alias already present in the map is never
overwritten — repointing one would change which class every historic row resolves to, application-wide.

`require_map` calls `Relation::requireMorphMap()` at boot, so Eloquent throws rather than storing a
fully qualified class name in a `*_type` column. Two things that buys: the column stops leaking your
class map into every audit export, and a renamed class stops silently orphaning the history that
referenced it.

**Off by default because that call is application-global.** Turning it on makes unmapped morphs throw
anywhere in your application — good practice, but not something a package switches on for you. The
package's own boundary does not depend on it either way: `targets.allowlist` is deny-by-default, so an
unaliased class cannot be impersonated regardless. Enabling it is defence in depth for the columns,
not the primary control.

## Authorization

```php
'authorization' => [
    'policy'       => null,             // null auto-selects; see `rbac.detect` below
    'gate_ability' => 'impersonate',
    'allow_nested' => false,

    // Which class names count as "a permission package is installed", probed with
    // class_exists(). Only picks a default — an explicit `policy` above wins.
    'rbac' => ['detect' => ['Spatie\\Permission\\PermissionServiceProvider']],

    'permissions' => [
        'enter'      => 'impersonator.enter',
        'mode'       => 'impersonator.mode.%s',
        'revoke'     => 'impersonator.revoke',
        'approve'    => 'impersonator.approve',
        'audit_view' => 'impersonator.audit.view',
    ],

    'roles' => [
        'protected' => ['super-admin'],
        'hierarchy' => null,
        'levels'    => ['super-admin' => 100, 'admin' => 80, 'manager' => 60, 'support' => 40, 'user' => 10],
    ],
],
```

`gate_ability` is consulted only when the application actually defines that ability — an
undefined ability denies everything in Laravel, so treating "not defined" as "denied" would break
every install that never opted in.

Entering requires **both** `enter` and the per-mode permission.

`rbac.detect` is how you point the auto-selection at a permission package other than spatie's — the
policy itself is duck-typed against `hasPermissionTo()` / `hasRole()`, so the class list is the only
spatie-specific thing in the package. For a rule a class list cannot express, register a closure:

```php
Impersonator::detectRbacUsing(fn (): bool => Acme::permissionsEnabled());
```

Both fail closed: anything other than a literal `true` selects the base policy. See
[Authorization](tools/authorization.md#choosing-what-counts-as-installed).

## Reason

```php
'reason' => [
    'require'    => env('IMPERSONATOR_REQUIRE_REASON', false),
    'min_length' => 3,
    'max_length' => 500,
],
```

Recommended anywhere impersonation touches customer data. It is the difference between a trail
that records what happened and one that records why.

## Limits

```php
'limits' => [
    'max_active_per_impersonator' => env('IMPERSONATOR_MAX_ACTIVE', 1),
    'deny_when_target_busy'       => env('IMPERSONATOR_DENY_WHEN_BUSY', false),
    'max_duration'                => env('IMPERSONATOR_MAX_DURATION', 10),
    'extension'                   => [...],   // see below
    'state_cache'                 => ['ttl' => 10],
],
```

`max_duration` is in minutes and null means unlimited, which is not recommended — an abandoned
session inside a customer account is the one that shows up in an audit with no explanation. The
doctor warns about it.

**Ten minutes by default.** Exposure should be measured by the length of the task, not the length of
a shift: most support work inside an account is a couple of minutes of looking, and the sessions that
run for an hour are usually the ones nobody remembered to close. Where the work genuinely takes
longer, extension is how an operator says so.

Concurrency caps are enforced inside a locked transaction, because a count-then-insert is a race
that two simultaneous requests both win.

## Operator-side controls

```php
'authorization' => [
    'recheck_each_request' => env('IMPERSONATOR_RECHECK_EACH_REQUEST', false),
    'step_up' => [
        'require'     => env('IMPERSONATOR_REQUIRE_STEP_UP', false),
        'within'      => env('IMPERSONATOR_STEP_UP_WITHIN', 900),   // seconds
        'session_key' => 'auth.password_confirmed_at',
    ],
],
'limits'  => ['max_idle' => env('IMPERSONATOR_MAX_IDLE')],   // minutes; null is off
'targets' => ['eligibility' => null],
```

All four are **off by default**, because each can refuse an impersonation an installation expects to
work. See [Operator-side controls](security.md#operator-side-controls) for what each one stops and why
it defaults off — `step_up` in particular needs a host-side `password.confirm` route, and turning it on
without one refuses everything.

## PostgreSQL row-level security

```php
'rls' => [
    'enabled'    => env('IMPERSONATOR_RLS_ENABLED', false),
    'connection' => env('IMPERSONATOR_RLS_CONNECTION'),
    'prefix'     => env('IMPERSONATOR_RLS_PREFIX', 'app'),
],
```

**The main RLS fix is not this switch.** It is reading `RlsContext::effective()` in your own scoping
layer instead of `auth()->id()`, which is one line — see
[Scope rows correctly under PostgreSQL RLS](recipes/scope-rows-with-postgres-rls.md). Without that, an
impersonated session sends the *operator's* id to the database and sees the operator's rows while
claiming to be the customer.

This switch adds the `impersonator.rls` middleware, which publishes the context as transaction-scoped
GUCs so a policy can also refuse writes under `read_only` at the database level. Defence in depth, not a
replacement: a write blocked only by a policy cannot be reported as a `ModeViolationBlocked` event.

## Extending a live impersonation

```php
'limits' => [
    'extension' => [
        'enabled'            => env('IMPERSONATOR_EXTENSION_ENABLED', true),
        'minutes'            => env('IMPERSONATOR_EXTENSION_MINUTES', 10),
        'max'                => env('IMPERSONATOR_EXTENSION_MAX', 3),
        'max_total_duration' => env('IMPERSONATOR_MAX_TOTAL_DURATION', 60),
        'within'             => env('IMPERSONATOR_EXTENSION_WITHIN', null),
    ],
],
```

Extension is what lets `max_duration` stay short. Without an escape valve the pressure is to raise
the window "just in case" — and a long window is the thing a short one exists to avoid. So the
default is small, and staying longer is a decision that gets recorded as one.

**Two independent bounds apply and the stricter wins.** Both are needed:

| Setting | Bounds | Why it is not enough alone |
|---|---|---|
| `max` | How many times | The window length is configurable, so a count bounds no amount of time |
| `max_total_duration` | Total minutes from the start | A total alone never asks the operator to re-justify |

Setting **both** to null makes `max_duration` advisory: an impersonation can then run indefinitely a
window at a time, which reads as a ten-minute limit and behaves as none. The doctor warns loudly
about exactly that combination.

`within` restricts extending to the final N minutes. Null allows it any time; set it to stop an
operator stacking the whole allowance the moment they enter, which would turn a ten-minute default
into an hour before any work started.

The last extension is **clamped to the ceiling rather than refused**, so the full allowance stays
usable — asking for ten more minutes when four remain under the ceiling grants four.

### Reaching it

```php
$outcome = Impersonator::extendSession();

$outcome->granted();                     // bool
$outcome->grant->seconds();              // actually added, which may be less than configured
$outcome->grant->decision->code;         // extension_limit, extension_ceiling, …
$outcome->session->expiresAt;            // the new deadline

Impersonator::canExtendSession();        // read-only: spends nothing, for rendering a button
```

Note this is **not** `Impersonator::extend()` — that is Laravel's driver-registration method,
inherited from the Manager convention. The two are unrelated.

The default banner renders an Extend button when the rules allow it, and `cannot extend` with the
reason when they do not — an operator needs to know before the session ends under them. Over HTTP:

| Route | Method | Notes |
|---|---|---|
| `impersonator.extend` | POST | The caller's own session; refuses with 403 and a `reason` code |
| `impersonator.api.impersonations.extend` | POST | `POST impersonations/current/extend` |

Neither takes an audit id. An operator may extend the session they are in and no other — prolonging
somebody else's access to an account on their behalf is not a thing to expose.

The extension is written inside a locked transaction, so two clicks on the button spend one
allowance rather than two. See [The security model](security.md#timed-impersonation).

## Rate limiting

```php
'rate_limiting' => [
    'enter'  => ['attempts' => 5,  'decay' => 60],
    'accept' => ['attempts' => 10, 'decay' => 60],
    'api'    => ['attempts' => 30, 'decay' => 60],
],
```

`decay` is in **seconds**. Entering and the API are keyed per operator rather than per IP: the risk
is one authorised person enumerating accounts, and they do it from a single address. `accept` is
keyed by IP instead, because the caller redeeming a handoff has no session on that host yet — the
token is the credential.

### Your own limits, while impersonating

Laravel's `throttle` keys on `$request->user()`, and during an impersonation that is the **target**.
So the operator's traffic spends the customer's allowance, and the customer can be locked out of
their own application by the person helping them. See
[Rate limits during impersonation](security.md#rate-limits-during-impersonation) for why that is
also a denial-of-service primitive.

Two ways to fix it in your application. For a route using `throttle:…` arguments, swap the
middleware:

```php
Route::middleware('impersonator.throttle:60,1')->group(function (): void {
    // Identical to `throttle:60,1` when nobody is impersonating.
});
```

For a named limiter, the closure owns the key, so ask for it:

```php
RateLimiter::for('api', function (Request $request) {
    $key = Impersonator::rateLimitKey($request)
        ?? (string) $request->user()?->getAuthIdentifier();

    return Limit::perMinute(60)->by($key);
});
```

`rateLimitKey()` returns null when no impersonation is active, so the `??` is the whole integration:
ordinary requests keep whatever key you already used.

## Tokens

```php
'tokens' => [
    'table'       => 'impersonator_tokens',
    'connection'  => null,
    'bytes'       => 40,
    'ttl'         => 60,          // seconds
],
```

40 bytes from `random_bytes`, with a 32-byte floor enforced in code. Sixty seconds is a handoff
window, not a session lifetime. See [The security model](security.md).

## Session

```php
'session' => [
    'key'               => 'impersonator',
    'destroy_on_revoke' => true,
],
```

`destroy_on_revoke` ends a revoked session out of band where the store allows it. With `cookie`
or `array` there is no server-side record to destroy, so the revocation is recorded and the
middleware ends the session on its next request.

## Audit

```php
'audit' => [
    'table'          => 'impersonator_audits',
    'connection'     => null,
    'retention_days' => env('IMPERSONATOR_AUDIT_RETENTION_DAYS'),
    'tamper_evident' => env('IMPERSONATOR_TAMPER_EVIDENT', false),
    'hash_key'       => env('IMPERSONATOR_AUDIT_HASH_KEY'),
],
```

`connection` lets a multi-tenant install keep impersonation records centrally while the
application runs per-tenant.

Turning `tamper_evident` on **requires** `hash_key`, and the provider throws if it is missing: a
chain written with a key nobody recorded cannot be verified later. Keep the key outside the
database — a chain whose key sits alongside the rows protects nothing. Retention is enforced via
`MassPrunable`, so `php artisan model:prune` does the work.

## Trail

```php
'trail' => [
    'table'            => 'impersonator_audit_events',
    'record_payloads'  => false,
    'redact'           => ['password', 'token', 'secret', 'authorization', '...'],
    'ignore_paths'     => ['telescope*', 'horizon*', '_debugbar*'],
],
```

Payload recording is off by default. When on, payloads are redacted recursively first — but
redaction is a filter, not a guarantee, which is exactly why it is off.

## Causer

```php
'causer' => [
    'resolver' => null,      // closure or invokable class
],
```

Who to attribute an action to. Defaults to the impersonator, since they are the person who
actually acted. See [The audit trail](tools/audit-trail.md).

## Routes

```php
'routes' => [
    'enabled'               => true,
    'prefix'                => 'impersonator',
    'middleware'            => ['web'],
    'enforcement'           => [/* the mode + lifetime middleware */],
    'auto_append_to_groups' => [],
],
```

`auto_append_to_groups` is how the enforcement middleware reaches *your* routes. Registering it
only on the package's own routes would enforce nothing, because the requests that need
constraining are the application's.

## URLs and redirects

```php
'urls' => [
    'base_domain' => env('IMPERSONATOR_BASE_DOMAIN'),
],

'redirects' => [
    'after_enter' => '/',
    'after_leave' => '/',
    'allowed_hosts' => [],
],
```

`redirect_to` accepts relative paths only unless a host is allowlisted. An open redirect on an
impersonation entry point is a credential-phishing primitive.

## Banner

```php
'banner' => [
    'enabled'      => true,
    'position'     => 'top',
    'display_name' => 'name',
    'show_mode'    => true,
],
```

## API

```php
'api' => [
    'enabled'      => env('IMPERSONATOR_API_ENABLED', false),
    'prefix'       => 'impersonator/api/v1',
    'middleware'   => ['api', 'auth:sanctum'],
    'per_page'     => 25,
    'max_per_page' => 100,
],
```

**Off by default.** An impersonation API is a remote-control surface for every account in the
system, and nobody should acquire one by upgrading a package. See
[The REST API](tools/rest-api.md).

## Notifications

```php
'notifications' => [
    'notify_target'       => env('IMPERSONATOR_NOTIFY_TARGET', false),
    'notify_target_delay' => 0,

    'security_channel' => [
        'enabled' => env('IMPERSONATOR_SECURITY_ALERTS', false),
        'mail'    => [],
        'webhook' => env('IMPERSONATOR_SECURITY_WEBHOOK'),
        'on'      => ['full_mode_enter', 'revoked'],
    ],

    'approvals' => [
        'enabled'          => env('IMPERSONATOR_NOTIFY_APPROVERS', false),
        'mail'             => [],
        'resolver'         => null,
        'notify_requester' => true,
    ],
],
```

Both off by default — enabling either changes what your users receive. The security channel
deliberately does not alert on routine `read_only` work: a channel that fires on everything is
one nobody reads. See [Notifications](tools/notifications.md).

## Approval

```php
'approval' => [
    'require'        => env('IMPERSONATOR_REQUIRE_APPROVAL', false),
    'ttl'            => 15,
    'except_modes'   => [Mode::READ_ONLY],
    'retention_days' => env('IMPERSONATOR_APPROVAL_RETENTION_DAYS'),
],
```

Four-eyes authorisation. `except_modes` is the point of the feature rather than a loophole:
requiring a second person for routine read-only work trains everyone to approve reflexively,
which is how the control becomes a rubber stamp. See [Break-glass approvals](tools/approvals.md).

## Doctor

```php
'doctor' => [
    'conflicting_packages' => [
        'Lab404\Impersonate\ImpersonateServiceProvider' => 'lab404/laravel-impersonate',
        // ...
    ],
],
```

Add whatever else you know conflicts. Nothing here is a hard conflict — two packages can coexist,
but leaving through one does not end an impersonation started by the other.

## Logging

```php
'logging' => [
    'enabled'         => true,
    'channel'         => env('IMPERSONATOR_LOG_CHANNEL'),
    'level'           => env('IMPERSONATOR_LOG_LEVEL', 'info'),
    'rejection_level' => env('IMPERSONATOR_LOG_REJECTION_LEVEL', 'warning'),
],
```

Refusals log at a higher level than successes, because they are the security-relevant half of the
signal. Raw token and credential values never appear.

---

[← Docs index](../README.md#documentation)
