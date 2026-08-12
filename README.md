# laranail/impersonator

[![Packagist Version](https://img.shields.io/packagist/v/laranail/impersonator.svg?style=flat-square)](https://packagist.org/packages/laranail/impersonator)
[![Tests](https://img.shields.io/github/actions/workflow/status/laranail/impersonator/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/laranail/impersonator/actions/workflows/tests.yml)
[![Static analysis](https://img.shields.io/github/actions/workflow/status/laranail/impersonator/static-analysis.yml?branch=main&label=static%20analysis&style=flat-square)](https://github.com/laranail/impersonator/actions/workflows/static-analysis.yml)
[![License MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)

> Laravel user impersonation with pluggable drivers and auth adapters, privilege-scoped
> impersonation modes, two-level audit trails, RBAC integration, remote revocation, break-glass
> approvals, and an optional REST API.

Requires PHP 8.3+ and Laravel 13. The only hard dependencies are `illuminate/*` and three PSR
interfaces. Sanctum, Passport, JWT, stancl/tenancy and spatie/laravel-permission are all optional —
install one and its integration activates itself.

## Install

```bash
composer require laranail/impersonator
```

```bash
php artisan vendor:publish --tag=impersonator-config
php artisan vendor:publish --tag=impersonator-migrations
php artisan migrate
```

Then name your user model, which is the one setting that has no sensible default:

```php
// config/impersonator.php
'targets' => [
    'allowlist' => ['user' => App\Models\User::class],
],
```

## Quick start

```php
use Simtabi\Laranail\Impersonator\Laravel\Facades\Impersonator;

Impersonator::enter($customer, mode: 'read_only', reason: 'Ticket #4182');
Impersonator::isImpersonating();     // true
Impersonator::leave();
```

```blade
<x-impersonate-button :user="$customer" />

{{-- once, in your layout --}}
<x-impersonation-banner />
```

Neither component needs a conditional: the button renders nothing when the operator may not
impersonate that account, and the banner renders nothing when nobody is impersonating.

To enforce modes and the kill switch, put the middleware on your own routes:

```php
// config/impersonator.php
'routes' => ['auto_append_to_groups' => ['web']],
```

Then check your setup:

```bash
php artisan laranail::impersonator.doctor
```

## The two axes

The design decision that shapes everything else: **how an impersonation is established** and **how
the target is authenticated** are independent, and the manager composes them.

| | `session` adapter | `sanctum` | `passport` | `jwt` |
|---|---|---|---|---|
| **`session` driver** | the common case | — | — | — |
| **`token` driver** | cross-domain handoff | issue a token to a client | ditto | ditto |
| **`tenancy` driver** | per-tenant browser | per-tenant API | ditto | ditto |

Collapsing these into one dimension is why most packages in this space cannot do the combinations.
Keeping them apart makes "hand a mobile client a read-only token for this customer, expiring in ten
minutes" a configuration rather than a fork.

## <a name="documentation"></a>Documentation

Full documentation is hosted at
**<https://opensource.simtabi.com/documentation/laranail/impersonator/>**.

### Guides

- [Installation](docs/installation.md) — requirements, publishing, the one setting you must change
- [Getting started](docs/getting-started.md) — impersonate, scope, audit, in about five lines
- [Configuration](docs/configuration.md) — every block, and what each one changes
- [Architecture](docs/architecture.md) — the layers, the two axes, and why each choice was made
- [Security model](docs/security.md) — what is guaranteed, how, and what is not promised
- [Comparison](docs/comparison.md) — versus lab404, octopyid, stechstudio and stancl
- [Release](docs/release.md) — versioning, what CI gates, the checklist

### Reference

- [Drivers](docs/tools/drivers.md) — session, cross-domain token handoff, per-tenant
- [Auth adapters](docs/tools/auth-adapters.md) — session, Sanctum, Passport, JWT
- [Impersonation modes](docs/tools/modes.md) — the privilege boundary, and custom enforcers
- [Authorization](docs/tools/authorization.md) — policies, permissions, protected roles, hierarchy
- [Impersonatable targets](docs/tools/targets.md) — multiple user models, each with its own guard
- [The audit trail](docs/tools/audit-trail.md) — two levels, causer, tamper evidence, export
- [Remote revocation](docs/tools/revocation.md) — the kill switch, and when it is immediate
- [Break-glass approvals](docs/tools/approvals.md) — four-eyes authorisation
- [Blade components](docs/tools/blade-components.md) — five drop-ins that render nothing when unused
- [Events](docs/tools/events.md) — fourteen, including the refusals
- [Notifications](docs/tools/notifications.md) — target disclosure, security channel, approvals
- [The REST API](docs/tools/rest-api.md) — eleven endpoints, off by default
- [Console commands](docs/tools/commands.md) — doctor, enter, export, verify, prune

### Recipes

- [Add an impersonate button](docs/recipes/add-an-impersonate-button.md)
- [Restrict support staff to read-only](docs/recipes/restrict-support-to-read-only.md)
- [Impersonate across domains](docs/recipes/impersonate-across-subdomains.md)
- [Impersonate an API client](docs/recipes/impersonate-an-api-client.md)
- [Impersonate a second user model](docs/recipes/impersonate-a-second-user-model.md)
- [Add a custom mode](docs/recipes/add-a-custom-mode.md)
- [Require approval for full access](docs/recipes/require-approval-for-full-access.md)
- [Kill an impersonation remotely](docs/recipes/kill-a-session-remotely.md)
- [Export for a compliance request](docs/recipes/export-for-a-compliance-request.md)
- [Turn on and verify tamper evidence](docs/recipes/verify-the-audit-chain.md)

### Project

- [OpenAPI specification](docs/openapi.yaml) — the REST contract, OpenAPI 3.1
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Stability

Pre-1.0. The public surface — the facade, the Core contracts, the config keys, and the event
classes — is what the test suite pins, and a breaking change to any of it will be called out in the
changelog.

While pre-1.0 this repository keeps a single moving `v0.1.0` tag per the laranail convention, so
`^0.1` picks up changes on the next `composer update`.

## Local development

```bash
composer install

vendor/bin/pest                          # 633 tests
vendor/bin/phpstan analyse               # level max, no baseline
vendor/bin/pint --test
vendor/bin/rector process --dry-run
```

Sanctum, Passport, JWT and stancl/tenancy are dev dependencies so their adapters are
integration-tested against the real packages. CI additionally runs the suite with all four
**removed**, which is what proves no hard dependency has crept in.

`src/Core` must import no `Illuminate` code; an architecture test enforces it.

## Sister packages

Part of the [laranail](https://github.com/laranail) family of Laravel package tools.

## Community

Questions and ideas belong in
[Discussions](https://github.com/laranail/impersonator/discussions); bugs in
[Issues](https://github.com/laranail/impersonator/issues).

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately to
`opensource@simtabi.com` — see [SECURITY.md](SECURITY.md), and never in a public issue.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Simtabi LLC.
