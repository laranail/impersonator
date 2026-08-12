<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * An impersonation outlived `limits.max_duration` and was force-ended.
 *
 * Fires alongside ImpersonationEnded. Distinct because an expiry is a control
 * working as designed rather than an incident, and usually warrants different
 * routing from a revocation even though both are involuntary.
 */
final readonly class ImpersonationExpired
{
    public function __construct(public ImpersonationSession $session) {}
}
