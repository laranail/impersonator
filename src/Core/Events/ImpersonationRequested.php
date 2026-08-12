<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;

/**
 * An impersonation was asked for, before any authorization ran.
 *
 * Fires for every attempt, including the ones about to be refused, so a listener
 * counting attempts sees the true rate rather than only the successes. Exactly one
 * of ImpersonationStarted, ImpersonationRejected or a pending handoff follows.
 *
 * Listeners must not assume the impersonation will happen, and must not mutate
 * anything on the strength of it — authorization has not been consulted yet.
 */
final readonly class ImpersonationRequested
{
    public function __construct(public ImpersonationRequest $request) {}
}
