<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Modes;

use Illuminate\Support\Str;
use Simtabi\Laranail\Impersonator\Core\Contracts\ModeEnforcer;
use Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * Writes allowed, except a configured deny-list — the recommended production mode.
 *
 * This is the useful middle: support staff can actually do their job, while the
 * account-takeover paths stay closed. The shipped defaults deny password changes,
 * two-factor changes, billing and account deletion, since those are the actions
 * where an impersonated session stops being support and becomes a takeover.
 *
 * Four independent axes, any of which can refuse: route name, path pattern, gate
 * ability, and model class. Four rather than one because the same protected
 * operation is reachable by different routes in different applications, and a
 * deny-list matched on only one axis is a deny-list with a way around it.
 *
 * Safe methods are always allowed: this mode narrows what can be changed, not what
 * can be read.
 */
final readonly class LimitedModeEnforcer implements ModeEnforcer
{
    public function __construct(private Settings $settings) {}

    public function mode(): string
    {
        return Mode::LIMITED;
    }

    public function check(AttemptedAction $action, ImpersonationSession $session): Decision
    {
        if ($this->deniedByAbility($action)) {
            return $this->deny($action, 'ability');
        }

        if ($this->deniedByModel($action)) {
            return $this->deny($action, 'model');
        }

        // Reading is never restricted here. Checked after abilities and models so a
        // denied ability on a GET route is still refused.
        if (! $action->isUnsafeMethod() && $action->modelClass === null) {
            return Decision::allow();
        }

        if ($this->deniedByRoute($action)) {
            return $this->deny($action, 'route');
        }

        if ($this->deniedByPath($action)) {
            return $this->deny($action, 'path');
        }

        return Decision::allow();
    }

    public function guardsPersistence(): bool
    {
        // The model deny-list can only be enforced at the persistence layer — a
        // route pattern cannot tell you which model a controller is about to write.
        return $this->settings->array('modes.limited.deny_models') !== [];
    }

    public function describe(): string
    {
        return 'Limited — you can act in this account, except on protected operations.';
    }

    private function deniedByRoute(AttemptedAction $action): bool
    {
        if ($action->routeName === null) {
            return false;
        }

        foreach ($this->settings->stringList('modes.limited.deny_routes') as $pattern) {
            if (Str::is($pattern, $action->routeName)) {
                return true;
            }
        }

        return false;
    }

    private function deniedByPath(AttemptedAction $action): bool
    {
        $path = ltrim($action->path, '/');

        if ($path === '') {
            return false;
        }

        foreach ($this->settings->stringList('modes.limited.deny_paths') as $pattern) {
            if (Str::is($pattern, $path) || Str::is(ltrim($pattern, '/'), $path)) {
                return true;
            }
        }

        return false;
    }

    private function deniedByAbility(AttemptedAction $action): bool
    {
        $denied = $this->settings->stringList('modes.limited.deny_abilities');

        foreach ($action->abilities as $ability) {
            if (in_array($ability, $denied, true)) {
                return true;
            }
        }

        return false;
    }

    private function deniedByModel(AttemptedAction $action): bool
    {
        if ($action->modelClass === null) {
            return false;
        }

        foreach ($this->settings->stringList('modes.limited.deny_models') as $class) {
            // is_a with a string subject so a subclass of a protected model is
            // protected too — otherwise extending the model is a bypass.
            if ($action->modelClass === $class || is_a($action->modelClass, $class, true)) {
                return true;
            }
        }

        return false;
    }

    private function deny(AttemptedAction $action, string $axis): Decision
    {
        return Decision::deny(
            Decision::MODE_FORBIDS_WRITE,
            'That operation is not permitted while impersonating.',
            array_filter([
                'axis' => $axis,
                'method' => $action->normalizedMethod(),
                'route' => $action->routeName,
                'path' => $action->path,
                'model' => $action->modelClass,
            ], static fn (mixed $value): bool => $value !== null && $value !== ''),
        );
    }
}
