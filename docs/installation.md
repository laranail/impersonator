# Installation

Install the package, publish the config, run one migration.

## Requirements

| Requirement | Version |
|---|---|
| PHP | `^8.3` (8.3, 8.4, 8.5) |
| Laravel | `^13.0` |

Nothing else is required. The only hard dependencies are `illuminate/*` and three PSR
interfaces — `psr/log`, `psr/clock` and `psr/event-dispatcher`. Sanctum, Passport, JWT,
stancl/tenancy and spatie/laravel-permission are all **optional**: install one and the matching
integration activates itself, install none and the package works on sessions alone.

## Install

```bash
composer require laranail/impersonator
```

The service provider is auto-discovered. There is nothing to register.

## Publish the configuration

```bash
php artisan vendor:publish --tag=impersonator-config
```

This writes `config/impersonator.php`. Publishing is not strictly required — the package ships
usable defaults — but you will want it: the target allowlist has to name your own user model
before anything can be impersonated.

## Run the migration

```bash
php artisan vendor:publish --tag=impersonator-migrations
php artisan migrate
```

Four tables are created:

| Table | Holds |
|---|---|
| `impersonator_audits` | One row per impersonation — the session-level record |
| `impersonator_audit_events` | One row per action taken while impersonating |
| `impersonator_tokens` | Single-use handoff tokens, stored as SHA-256 digests |
| `impersonator_approval_requests` | Break-glass approvals |

The migration is published rather than loaded from the package so the schema is yours: you can
change the connection, add indexes for your own reporting, or rename a table through config.

## Name your user model

The one change you must make. Open `config/impersonator.php` and set the allowlist:

```php
'targets' => [
    'allowlist' => [
        'user' => App\Models\User::class,
    ],
],
```

This is an **allowlist, not a convenience**. A request naming any other class is refused before
the target is loaded, which is what stops arbitrary model injection through a form field. An
empty allowlist refuses everything.

More than one user model is supported — see [Impersonatable targets](tools/targets.md).

## Optional: publish the views

```bash
php artisan vendor:publish --tag=impersonator-views
```

Only needed if you want to restyle the banner. The Blade components work without this.

## Verify the install

```bash
php artisan laranail::impersonator.doctor
```

The doctor reports the problems that produce no error — a guard that does not exist, an operator
who can enter but cannot choose a mode, a revocation switch that cannot actually end a session.
Run it now and after every configuration change. See [The doctor command](tools/commands.md).

---

[← Docs index](../README.md#documentation)
