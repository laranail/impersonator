<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;

/**
 * An impersonation attempt was refused.
 *
 * The security-relevant half of the signal, and the half most packages do not
 * emit at all: a successful impersonation is expected, whereas an operator
 * repeatedly probing accounts they may not reach is what an alert should fire
 * on. Carries the full Decision, so the code is available for routing without
 * parsing a message.
 */
final readonly class ImpersonationRejected
{
    public function __construct(
        public ImpersonationRequest $request,
        public Decision $decision,
    ) {}
}
