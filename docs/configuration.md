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
    'sanctum'  => ['ttl' => 30, 'abilities' => ['*']],
    'passport' => ['ttl' => 30, 'scopes' => []],
    'jwt'      => ['ttl' => 30],
],
```

Per-adapter TTL in minutes and ability/scope narrowing.

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
    'read_only' => [ /* ... */ ],
    'limited'   => ['abilities' => [], 'models' => [], 'routes' => [], 'paths' => []],
    'full'      => [],
],
```

The privilege boundary. `read_only` blocks writes at the persistence layer; `limited` narrows to
allowlisted abilities, models, routes or paths; `full` is everything the target can do.
Registering your own mode means registering a `ModeEnforcer` with it — a mode that is selectable
but not enforced reports a restriction it is not applying. See
[Impersonation modes](tools/modes.md).

## Authorization

```php
'authorization' => [
    'policy'       => null,             // null auto-selects: RBAC when spatie is installed
    'gate_ability' => 'impersonate',
    'allow_nested' => false,

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

Entering requires **both** `enter` and the per-mode permission. See
[Authorization](tools/authorization.md).

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
    'max_duration'                => env('IMPERSONATOR_MAX_DURATION', 60),
    'state_cache'                 => ['ttl' => 10],
],
```

`max_duration` is in minutes and null means unlimited, which is not recommended — an abandoned
session inside a customer account is the one that shows up in an audit with no explanation. The
doctor warns about it.

Concurrency caps are enforced inside a locked transaction, because a count-then-insert is a race
that two simultaneous requests both win.

## Rate limiting

```php
'rate_limiting' => [
    'enter'  => ['attempts' => 10, 'per_minutes' => 1],
    'accept' => ['attempts' => 10, 'per_minutes' => 1],
    'api'    => ['attempts' => 30, 'per_minutes' => 1],
],
```

Entering is limited per operator rather than per IP: the risk is one authorised person
enumerating accounts, and they do it from a single address.

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
