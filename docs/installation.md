# Installation

Install the package, publish the config, run one migration.

## Requirements

| Requirement | Version |
|---|---|
| PHP | `^8.4.1 \|\| ^8.5` (8.4, 8.5) |
| Laravel | `^13.0` |
| Database | SQLite, PostgreSQL, MySQL — see below |

**The floor is 8.4.1, not 8.4.0.** It is inherited rather than chosen: `laranail/console` declares
`^8.4.1` so that its optional `symfony/tui` integration is usable. That package is only a *suggest*
and is not installed here — but the floor its presence implies applies to anything depending on
console, and Composer resolves this package to it regardless. Nothing in this package's own code
needs 8.4.

Hard dependencies are `illuminate/*`, three PSR interfaces — `psr/log`, `psr/clock` and
`psr/event-dispatcher` — and four `laranail/*` packages:

| Package | Used for |
|---|---|
| `laranail/package-tools` | The service-provider base and the shared doctor subsystem |
| `laranail/console` | The `laranail::` Artisan command base — and the 8.4.1 floor |
| `laranail/enumerator` | Translatable enum labels — the only one reaching into `src/Core` |
| `laranail/db-tools` | Connection resolution and non-throwing schema probes |

These resolve through **git VCS repositories, not Packagist** — see [Install](#install).

Between them they add only two third-party packages a Laravel application would not already have:
`brick/money` and `spatie/laravel-sluggable`, both transitive through `db-tools`. Neither is used by
this package; they come from that dependency's own breadth.

> **Symfony 8 is required.** Laravel 13 itself accepts `^7.4 || ^8.0`, but `laranail/console` pins
> `symfony/console ^8.0`. An application held on Symfony 7 cannot install this package, and the
> conflict Composer reports will name `symfony/console` rather than anything here.

Sanctum, Passport, JWT, stancl/tenancy and spatie/laravel-permission remain **optional**: install one
and the matching integration activates itself, install none and the package works on sessions alone.

### Databases

| Driver | Status |
|---|---|
| SQLite | Tested in CI on every push. Note `lockForUpdate()` compiles to nothing here, so the concurrency guarantees are not provable on it — the `locking` group skips itself rather than passing |
| PostgreSQL 17 | Tested in CI on every push, whole suite, with the `locking` group asserted to actually run |
| MySQL 8.4 | Tested in CI on every push, same as PostgreSQL |
| MariaDB | Expected to work; not tested. It shares MySQL's grammar and locking, so the risk is low |
| SQL Server | **Parsing verified, behaviour untested** — see below |

The three tested drivers are exercised with the *whole* suite rather than a subset, because a driver
difference can surface anywhere: the defect that broke `read_only` outright on PostgreSQL and MySQL was
in mode enforcement, not in a concurrency test, and it survived a green SQLite run for a release.

#### What is and is not known about SQL Server

Laravel ships the SQL Server *grammar*, and a connection can be configured without ever being opened —
`toSql()` compiles locally and touches no server. So two things are **verified in the suite**:

- The mode guard parses SQL Server's quoting, including two- and three-part names
  (`[dbo].[impersonator_audits]`, `[db].[dbo].[impersonator_audits]`). This is the same defect class that
  broke `read_only` on PostgreSQL for a release, so it is tested rather than assumed.
- `lockForUpdate()` compiles to `with(rowlock, updlock, holdlock)` there — a table hint, **not** the
  `for update` that PostgreSQL and MySQL emit.

What is **not** verified is behaviour: that those hints take the locks the concurrency guarantees need.
That requires a real server, and it is not currently reachable here — the `pdo_sqlsrv` extension is not
available for this package's PHP floor through PECL, so there is no CI job. Adding one that fails for
driver-availability reasons would make CI red about something other than this package.

So: **use SQL Server if you need it, and treat the concurrency guarantees as unproven there.** Those are
the impersonation cap, the single-use token claim, the approval quorum recount and the extension
allowance. Everything else — the modes, the trail, the audit chain, the API — is driver-independent.

## Install

The `laranail/*` family resolves through git, not Packagist. **Composer ignores a dependency's own
`repositories` block**, so the whole `laranail/*` closure has to be declared in *your* root
`composer.json` — listing only `impersonator` fails to resolve its siblings:

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/laranail/impersonator" },
        { "type": "vcs", "url": "https://github.com/laranail/console" },
        { "type": "vcs", "url": "https://github.com/laranail/db-tools" },
        { "type": "vcs", "url": "https://github.com/laranail/enumerator" },
        { "type": "vcs", "url": "https://github.com/laranail/package-tools" }
    ]
}
```

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

Five tables are created:

| Table | Holds |
|---|---|
| `impersonator_audits` | One row per impersonation — the session-level record |
| `impersonator_audit_events` | One row per action taken while impersonating |
| `impersonator_tokens` | Single-use handoff tokens, stored as SHA-256 digests |
| `impersonator_approval_requests` | Break-glass approvals |
| `impersonator_approval_decisions` | One row per reviewer, for multi-reviewer chains |

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

## Optional: translate or reword the messages

```bash
php artisan vendor:publish --tag=impersonator-lang
```

Eight files land in `lang/vendor/impersonator/en/`. English is the only locale shipped; add a sibling
directory to translate, or edit `en` to reword. Published lines win over the package's own, so
changing one sentence does not mean forking a file.

| File | Covers |
|---|---|
| `decisions.php` | Every refusal, keyed by its `Decision` code |
| `exceptions.php` | Messages that reach a caller as an exception |
| `notifications.php` | Customer and staff mail |
| `banner.php` | The impersonation banner |
| `modes.php` | Mode display names |
| `components.php` | Blade button labels |
| `validation.php` | Form Request messages |
| `console.php` | Artisan output |

Three things worth knowing before you translate:

- **A missing key falls back to English.** Nothing renders blank or as a raw `impersonator::…` key, so
  a partial translation is a valid state. Delete a line you do not want to override.
- **The `reason` code in an API response is never translated.** It is the stable contract; `message`
  is the display text. Branch on `reason`. See [The REST API](tools/rest-api.md#refusals).
- **`exceptions.token_rejected` is one line for four different failures**, and that is deliberate.
  Splitting it by reason would tell somebody probing the accept route whether a token was real. See
  [Handoff tokens](security.md#handoff-tokens).

Several codes nest under a sub-key — `session_terminated.revoked` and `session_terminated.expired`,
for instance — because more than one sentence shares that code. Keep the nesting; a bare string in its
place would collapse them all into one message.

The doctor's diagnostic paragraphs are deliberately **not** translatable. They name config keys and
artisan commands inline, and a half-translated paragraph wrapped around untranslatable identifiers
reads worse than English. Its labels and counted summaries are in `console.php`.

## Verify the install

```bash
php artisan laranail::impersonator.doctor
```

The doctor reports the problems that produce no error — a guard that does not exist, an operator
who can enter but cannot choose a mode, a revocation switch that cannot actually end a session.
Run it now and after every configuration change. See [The doctor command](tools/commands.md).

---

[← Docs index](../README.md#documentation)
