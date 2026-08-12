<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * An administrator killed an impersonation they did not own.
 *
 * Fires in addition to ImpersonationEnded, not instead of it: a listener that only
 * cares that access ended stays correct, while one that alerts on intervention can
 * subscribe here without inspecting a reason code.
 *
 * Note the revocation is *recorded* at this point; the target's session is refused
 * on its next request, since a session can only be ended from inside itself.
 */
final readonly class ImpersonationRevoked
{
    public function __construct(
        public ImpersonationSession $session,
        public ?Identity $revokedBy = null,
        public ?string $note = null,
    ) {}
}
