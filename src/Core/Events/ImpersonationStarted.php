<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * An impersonation became live — the target is authenticated.
 *
 * Deliberately not fired for a pending cross-domain handoff: at that point a
 * token has been issued but nobody has been impersonated, and a listener that
 * treated the two alike would notify a user their account was accessed when it
 * was not.
 *
 * A plain PHP object with no framework base class, so Laravel's dispatcher and a
 * PSR-14 dispatcher can both carry it.
 */
final readonly class ImpersonationStarted
{
    public function __construct(public ImpersonationSession $session) {}
}
