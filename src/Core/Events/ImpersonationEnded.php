<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * An impersonation stopped, for any of the four reasons.
 *
 * One event rather than four carries the reason as data, so a listener that only
 * cares that access ended does not have to subscribe to every terminal case —
 * and a reason added later does not silently bypass existing listeners. Check
 * `$reason->isInvoluntary()` to single out the ones an operator did not choose.
 */
final readonly class ImpersonationEnded
{
    public function __construct(
        public ImpersonationSession $session,
        public EndReason $reason,
    ) {}
}
