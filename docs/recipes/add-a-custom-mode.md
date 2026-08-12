# Add a custom mode

Register a privilege scope of your own, with the enforcer that gives it meaning.

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

    public function guardsPersistence(): bool
    {
        return false;   // true also checks every query, as `read_only` does
    }

    public function describe(): string
    {
        return 'Billing operations only.';
    }
}
```

```php
// A service provider's boot()
Impersonator::registerMode(new BillingOnlyEnforcer);
```

```php
Impersonator::enter($customer, mode: 'billing_only');
```

The registry pairs a mode with its enforcer, so a mode cannot be registered without one — a mode
that is selectable but not enforced is worse than not offering it.

With spatie/laravel-permission installed this also implies a new permission,
`impersonator.mode.billing_only`, which operators need alongside `impersonator.enter`.

Reference: [Impersonation modes](../tools/modes.md).

---

[← Docs index](../../README.md#documentation)
