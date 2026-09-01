<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Modes;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Simtabi\Laranail\Impersonator\Core\Contracts\ModeEnforcer;
use Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Throwable;

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

        // Before the route and path axes, because under Livewire those two cannot see anything: every
        // action arrives on one route with one path, so this is the only axis that can tell them apart.
        if ($this->deniedByLivewire($action)) {
            return $this->deny($action, 'livewire');
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

    /**
     * Whether a Livewire component or method is denied.
     *
     * Matched with `Str::is` against every identifier the payload yields — the qualified
     * `Component::method`, the bare component, and the bare method — so a rule can be written at
     * whichever granularity fits:
     *
     *   'ProfileForm::updatePassword'   one action
     *   'ProfileForm::*'                a whole component
     *   '*::destroy'                    a method wherever it appears
     *
     * This exists because `deny_routes` and `deny_paths` are inert under Livewire: one endpoint serves
     * every action, so a rule naming a route matches nothing and a rule broad enough to match blocks the
     * application. Without this axis, `limited` was substantially weaker under Livewire than it looked.
     */
    private function deniedByLivewire(AttemptedAction $action): bool
    {
        $identifiers = $action->livewireIdentifiers();

        if ($identifiers === []) {
            return false;
        }

        $patterns = $this->settings->stringList('modes.limited.deny_livewire');

        return array_any(
            $patterns,
            static fn (string $pattern): bool => array_any(
                $identifiers,
                static fn (string $identifier): bool => Str::is($pattern, $identifier),
            ),
        );
    }

    private function deniedByRoute(AttemptedAction $action): bool
    {
        if ($action->routeName === null) {
            return false;
        }

        return array_any($this->settings->stringList('modes.limited.deny_routes'), fn (string $pattern) => Str::is($pattern, $action->routeName));
    }

    private function deniedByPath(AttemptedAction $action): bool
    {
        $path = ltrim($action->path, '/');

        if ($path === '') {
            return false;
        }

        return array_any($this->settings->stringList('modes.limited.deny_paths'), fn (string $pattern): bool => Str::is($pattern, $path) || Str::is(ltrim($pattern, '/'), $path));
    }

    private function deniedByAbility(AttemptedAction $action): bool
    {
        $denied = $this->settings->stringList('modes.limited.deny_abilities');

        return array_any($action->abilities, fn (string $ability): bool => in_array($ability, $denied, true));
    }

    /**
     * The model deny-list, matched on either a class name or a table name.
     *
     * Both forms arrive, and only handling the first is a silent hole. An Eloquent-level check
     * knows the class; the persistence guard sees a bare SQL statement and can only name the
     * **table** it writes to. Comparing a table name against configured class names never matches,
     * so a deny-list configured as `[PaymentMethod::class]` would have read as protection while
     * enforcing nothing — and the persistence guard is the only layer that can enforce this axis at
     * all, since a route pattern cannot tell you which model a controller is about to write.
     *
     * So a table name is resolved the other way: each configured class is asked for its own table,
     * and those are compared. Classes are still matched with `is_a` so a subclass of a protected
     * model stays protected — otherwise extending the model is a bypass.
     */
    private function deniedByModel(AttemptedAction $action): bool
    {
        if ($action->modelClass === null) {
            return false;
        }

        $subject = $action->modelClass;
        $subjectIsClass = class_exists($subject);

        foreach ($this->settings->stringList('modes.limited.deny_models') as $class) {
            if ($subject === $class) {
                return true;
            }

            if ($subjectIsClass && is_a($subject, $class, true)) {
                return true;
            }

            if (! $subjectIsClass && $this->tableFor($class) === strtolower($subject)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The table a denied model class writes to, lowercased, or null when it cannot be determined.
     *
     * Instantiating the model is the only reliable way to ask: the table may be set explicitly, or
     * derived from the class name by Eloquent's own pluralisation, and reimplementing that
     * derivation here would drift from whatever the framework does next.
     */
    private function tableFor(string $class): ?string
    {
        if (! class_exists($class) || ! is_a($class, Model::class, true)) {
            return null;
        }

        try {
            $model = new $class;

            return strtolower($model->getTable());
        } catch (Throwable) {
            // A model whose constructor needs arguments cannot be asked. Treated as
            // unresolvable rather than as a match: guessing here would deny writes to an
            // unrelated table that happened to share a name.
            return null;
        }
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
