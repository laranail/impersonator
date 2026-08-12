# Contributing

Thanks for helping improve `laranail/impersonator`.

## Getting set up

```bash
composer install
composer test
```

## Before opening a pull request

All four have to be clean; CI runs the same commands.

```bash
composer test      # Pest, including the architecture suite
composer pint      # code style (Laravel preset, strict types)
composer phpstan   # static analysis at max level
composer rector    # dry-run; the php83 rule set
```

Use `composer pint-fix` and `composer rector-fix` to apply the mechanical fixes.

## The layering rule

The package is two layers, and the boundary is enforced by
`tests/Arch/LayeringTest.php` rather than by review:

- **`src/Core`** is pure PHP domain logic. It may import PSR interfaces
  (`psr/log`, `psr/clock`, `psr/event-dispatcher`) and its own contracts, and
  nothing else. No `Illuminate\*`, and no framework helper functions.
- **`src/Laravel`** is the bridge: the service provider, Eloquent
  implementations, middleware, routes, Blade, config, facade and commands.

If a change needs framework behaviour inside a Core class, the answer is a new
method on a Core contract that the bridge implements — not an import.

## Tests

Tests ship with the change, not afterwards.

- `tests/Unit` and `tests/Arch` run without an application container. Keep them
  that way: a Core test that needs a container is telling you the Core class has
  a dependency it should not have.
- `tests/Feature` boots Testbench.

Security-relevant behaviour needs a **failing-path** test, not just a passing
one. A test proving the happy path works says nothing about whether the control
holds. At minimum, anything touching token redemption, nesting,
self-impersonation, protected roles, permission bleed, revocation, mode
enforcement, redirects, target allowlisting, payload redaction, or concurrency
caps needs a test that asserts the refusal.

## Commits

- Subject in the imperative mood, 72 characters or fewer.
- The body explains *why*, not *what* — the diff already covers what.
- No emoji.

## Adding a driver, an adapter, or a mode

These are the three extension points, and none of them require a change to this
package:

```php
Impersonator::extend('my-driver', fn ($app) => new MyDriver(...));
Impersonator::extendAdapter('my-adapter', fn ($app) => new MyAdapter(...));
Impersonator::registerMode(new MyModeEnforcer);
```

A custom `ModeEnforcer` may only ever *narrow* what the target could already do.
An enforcer that permits something the target lacks permission for is a privilege
escalation, not a custom mode.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md) —
report privately to `opensource@simtabi.com`.
