<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Illuminate\Session\SessionManager;
use Illuminate\Session\Store;
use SessionHandlerInterface;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;
use Throwable;

/**
 * Whether a revocation can actually end a session, or only record the intent.
 *
 * The difference matters operationally. With a server-side session store the kill switch is
 * immediate; with `cookie` or `array` there is nothing to destroy from outside, so the session ends
 * on its next request — which for an idle tab could be a long time.
 */
final class SessionTerminationCheck extends Check
{
    public function name(): string
    {
        return 'Session termination';
    }

    public function description(): string
    {
        return 'Whether a revocation ends the session immediately or only on its next request.';
    }

    public function run(): DoctorResult
    {
        $driver = config('session.driver');
        $driver = is_string($driver) ? $driver : 'unknown';

        if (! $this->settings->bool('session.destroy_on_revoke', true)) {
            return DoctorResult::warn(
                'impersonator.session.destroy_on_revoke is off, so a revocation is only recorded. '
                . 'The impersonated session ends on its next request, which for an idle tab may be a while.',
            );
        }

        if (in_array($driver, ['cookie', 'array'], true)) {
            return DoctorResult::warn(sprintf(
                'The [%s] session driver keeps no server-side record, so a revocation cannot be '
                . 'enforced out of band — it is recorded and the middleware ends the session on its '
                . 'next request. Use database, redis or file for an immediate kill switch.',
                $driver,
            ));
        }

        try {
            $store = $this->container->make(SessionManager::class)->driver();
            $handler = $store instanceof Store ? $store->getHandler() : null;
        } catch (Throwable $e) {
            return DoctorResult::warn(sprintf('The session store could not be inspected: %s', $e->getMessage()));
        }

        return $handler instanceof SessionHandlerInterface
            ? DoctorResult::pass(sprintf('The [%s] driver can be destroyed out of band; revocation is immediate.', $driver))
            : DoctorResult::warn(sprintf('The [%s] driver exposes no destroyable handler.', $driver));
    }
}
