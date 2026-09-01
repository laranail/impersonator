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
 * Look, don't touch: unsafe HTTP methods are refused.
 *
 * The allowlist exists so a mode can never trap an operator inside an account —
 * leaving and logging out stay reachable no matter what, which would otherwise be
 * worse than having no mode at all.
 *
 * Method checking cannot see a write reached through a GET route, a queued job, a
 * Livewire action or a raw query, so `modes.read_only.prevent_writes` adds a
 * persistence-level net. It is **on by default**: a mode named read_only that
 * permits a write behind a GET is not read-only, and the guarantee is the whole
 * reason to offer the mode.
 */
final readonly class ReadOnlyModeEnforcer implements ModeEnforcer
{
    public function __construct(private Settings $settings) {}

    public function mode(): string
    {
        return Mode::READ_ONLY;
    }

    public function check(AttemptedAction $action, ImpersonationSession $session): Decision
    {
        // A write intercepted at the persistence layer, which by definition has no
        // safe method to be judged on.
        if ($action->modelClass !== null && $action->normalizedMethod() !== 'ABILITY') {
            return $this->isAllowedRoute($action)
                ? Decision::allow()
                : Decision::deny(
                    Decision::MODE_FORBIDS_WRITE,
                    'This impersonation is read-only, so nothing can be changed.',
                    ['detail' => 'read_only_persistence', 'model' => $action->modelClass, 'operation' => $action->normalizedMethod()],
                );
        }

        if (in_array($action->normalizedMethod(), $this->allowedMethods(), true)) {
            return Decision::allow();
        }

        if ($this->isAllowedRoute($action)) {
            return Decision::allow();
        }

        return Decision::deny(
            Decision::MODE_FORBIDS_WRITE,
            'This impersonation is read-only, so that action is not permitted.',
            ['detail' => 'read_only', 'method' => $action->normalizedMethod(), 'route' => $action->routeName, 'path' => $action->path],
        );
    }

    public function guardsPersistence(): bool
    {
        return $this->settings->bool('modes.read_only.prevent_writes', true);
    }

    public function describe(): string
    {
        return 'Read-only — you can view this account but not change anything.';
    }

    /** @return list<string> */
    private function allowedMethods(): array
    {
        $methods = $this->settings->stringList('modes.read_only.allowed_methods');

        // Falling back rather than defaulting to empty: an empty allowed_methods
        // would refuse GET, which is every page of the application.
        if ($methods === []) {
            return ['GET', 'HEAD', 'OPTIONS'];
        }

        return array_map(strtoupper(...), $methods);
    }

    /**
     * The escape hatch that keeps leave reachable. Matched on the route name and on
     * the path, because an application that renamed its logout route should not
     * thereby lock operators in.
     */
    private function isAllowedRoute(AttemptedAction $action): bool
    {
        $allowed = $this->settings->stringList('modes.read_only.allowed_routes');

        foreach ($allowed as $pattern) {
            if ($action->routeName !== null && Str::is($pattern, $action->routeName)) {
                return true;
            }

            if ($action->path !== '' && Str::is($pattern, ltrim($action->path, '/'))) {
                return true;
            }
        }

        return false;
    }
}
