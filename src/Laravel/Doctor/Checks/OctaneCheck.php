<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Illuminate\Contracts\Events\Dispatcher;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

/**
 * Whether the between-request resets are actually wired, when they matter.
 *
 * A named failure mode in exactly this problem domain: `stechstudio/filament-impersonate` #146 is
 * "impersonation targets the wrong user under Octane/Swoole". Under a long-running process a singleton
 * holding request state answers for the next request, and here that means somebody else's session.
 *
 * Reports a pass when Octane is absent, because there is then nothing to get wrong.
 */
final class OctaneCheck extends Check
{
    public function name(): string
    {
        return 'Octane';
    }

    public function description(): string
    {
        return 'Whether per-request state is reset between requests on a long-running server.';
    }

    public function run(): DoctorResult
    {
        if (! class_exists('Laravel\\Octane\\Octane')) {
            return DoctorResult::pass('Octane is not installed, so nothing holds state between requests.');
        }

        $events = $this->resolve(Dispatcher::class);

        if ($events === null) {
            return DoctorResult::skip('The event dispatcher could not be resolved, so this was not checked.');
        }

        // Both boundaries: a request that dies hard never reaches RequestTerminated, so relying on it
        // alone would leave the guard armed for whoever the worker serves next.
        $missing = array_values(array_filter(
            ['Laravel\\Octane\\Events\\RequestReceived', 'Laravel\\Octane\\Events\\RequestTerminated'],
            static fn (string $event): bool => ! $events->hasListeners($event),
        ));

        return $missing === []
            ? DoctorResult::pass('Octane is installed and the between-request resets are registered.')
            : DoctorResult::fail(
                'Octane is installed but the between-request reset is not registered for: '
                .implode(', ', $missing)
                .'. A singleton holding request state will answer for the next request, which in this '
                .'package means somebody else\'s impersonation.',
                ['missing' => $missing],
            );
    }
}
