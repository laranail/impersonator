<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Listeners;

use Illuminate\Contracts\Container\Container;
use Simtabi\Laranail\Impersonator\Core\Support\FailureReport;
use Simtabi\Laranail\Impersonator\Laravel\Support\PersistenceGuard;
use Throwable;

/**
 * Clears the two singletons that hold **request** state, between requests.
 *
 * Octane, a queue worker and `artisan serve --workers` all keep the container alive across requests,
 * so a singleton that remembers something about one request answers for the next. In an impersonation
 * package that is not a tidiness concern: `stechstudio/filament-impersonate` #146 is *"impersonation
 * targets the wrong user under Octane/Swoole"*, and wrong-user is a data-exposure bug.
 *
 * ### Why exactly two
 *
 * The seventeen singletons were audited for mutable properties rather than assumed about. Most hold
 * either nothing (`Settings`, `MessageCatalog`, `RedirectGuard`, `IdentityResolver` and `SessionState`
 * are `readonly` classes) or **boot-time registrations** that must survive — the manager's driver and
 * adapter factories, `ReviewerDirectory`'s eligibility closure, `ModeRegistry`'s enforcers,
 * `TargetRegistry`'s runtime types. Resetting those would delete a custom driver an application
 * registered in its provider, which is a worse bug than the one being fixed.
 *
 * Two do hold request state:
 *
 *  - **`PersistenceGuard`** is armed for one request with one impersonation. The middleware disarms it
 *    in a `finally`, so this is the belt to that braces — a worker killed mid-request, or a fatal that
 *    unwinds past the middleware, would otherwise leave the next request enforcing a stranger's mode.
 *  - **`FailureReport`** accumulates degraded state with no expiry. Under a long-running process one
 *    transient boot blip makes `isHealthy()` false for the life of the worker, so the doctor and every
 *    health probe report degraded forever after a single failure. `flush()` existed for this and
 *    nothing called it.
 *
 * `TargetRegistry`'s memo is deliberately **not** cleared: it caches a config read, which is exactly
 * what you want warm in a long-running process.
 *
 * Registered by event *name* rather than by class, so no `class_exists` probe and no dependency on
 * Octane — without it these names are simply never dispatched.
 */
final readonly class ResetImpersonatorState
{
    public function __construct(private Container $app) {}

    public function handle(): void
    {
        $this->disarmGuard();
        $this->flushReport();
    }

    /**
     * Resolved only if already resolved.
     *
     * `resolved()` before `make()` throughout: building a singleton in order to reset it would
     * construct the whole audit store on every request boundary — and worse, would throw on an install
     * with tamper evidence on and no key, turning a state reset into a fatal error between requests.
     */
    private function disarmGuard(): void
    {
        if (! $this->app->resolved(PersistenceGuard::class)) {
            return;
        }

        try {
            $guard = $this->app->make(PersistenceGuard::class);

            if ($guard instanceof PersistenceGuard) {
                $guard->disarm();
            }
        } catch (Throwable) {
            // A reset that throws would take down the worker between requests, which is strictly worse
            // than a stale guard: the next request's middleware arms it again before any query runs.
        }
    }

    private function flushReport(): void
    {
        if (! $this->app->resolved(FailureReport::class)) {
            return;
        }

        try {
            $report = $this->app->make(FailureReport::class);

            if ($report instanceof FailureReport) {
                $report->flush();
            }
        } catch (Throwable) {
            // As above. A degraded report that lingers is a reporting fault, not a security one.
        }
    }
}
