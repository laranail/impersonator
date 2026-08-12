<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/** A handoff token was successfully redeemed and the impersonation is now live. */
final readonly class HandoffTokenRedeemed
{
    public function __construct(public ImpersonationSession $session) {}
}
