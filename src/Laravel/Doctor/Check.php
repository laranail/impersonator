<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor;

use Illuminate\Contracts\Container\Container;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorCheck;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;
use Throwable;

/**
 * The shared base for this package's diagnostics.
 *
 * Every check exists because the failure it catches produces **no error**: impersonation appears to
 * work and the gap only surfaces during an incident or an audit. A missing table throws on first use
 * and needs no doctor; an operator who can enter but not choose a mode, or a revocation switch that
 * cannot actually end a session, passes every smoke test.
 *
 * Two responsibilities beyond the shorthands:
 *
 *  - **`run()` must never throw**, which the `DoctorCheck` contract requires and this package needs
 *    for a sharper reason. The audit store throws outright when tamper evidence is on without a key,
 *    so anything reaching it explodes on exactly the misconfigured install somebody is running the
 *    doctor to diagnose. {@see safely()} turns that into a diagnosis.
 *  - **Nothing container-resolved is constructor-injected.** For the same reason: a check that took
 *    `ImpersonationManager` in its constructor would fail to build rather than report, and a doctor
 *    that cannot start is no use on a broken install.
 */
abstract class Check implements DoctorCheck
{
    public function __construct(
        protected readonly Settings $settings,
        protected readonly Container $container,
    ) {}

    /**
     * Resolve a service, or null if the container refuses.
     *
     * @template T of object
     *
     * @param  class-string<T>  $service
     * @return T|null
     */
    protected function resolve(string $service): ?object
    {
        try {
            $instance = $this->container->make($service);
        } catch (Throwable) {
            return null;
        }

        return $instance instanceof $service ? $instance : null;
    }

    /**
     * Run a body that may throw, reporting the throw rather than propagating it.
     *
     * A failure to *inspect* is reported as a failure of the check, not silently as a pass — "I could
     * not tell" and "it is fine" are different answers, and collapsing them is how a doctor comes to
     * reassure somebody about a system it never looked at.
     *
     * @param  callable(): DoctorResult  $body
     */
    protected function safely(callable $body, string $whileDoing): DoctorResult
    {
        try {
            return $body();
        } catch (Throwable $e) {
            return DoctorResult::fail(
                sprintf('Could not %s: %s', $whileDoing, $e->getMessage()),
                ['exception' => $e::class],
            );
        }
    }
}
