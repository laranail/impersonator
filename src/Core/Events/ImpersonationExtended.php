<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\ExtensionGrant;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * An operator bought more time inside a live impersonation.
 *
 * Worth its own event, and worth logging: the point of a short window is that staying
 * longer is a decision somebody made rather than a default nobody noticed. A trail showing
 * three extensions on one account answers a question that a single row reading "fifty
 * minutes" cannot.
 *
 * `$session` is the state **after** the extension, so `expiresAt` is the new deadline and
 * `extensions` the new count. The grant carries what changed — how many seconds were
 * actually added, which may be fewer than configured where the ceiling clamped it.
 */
final readonly class ImpersonationExtended
{
    public function __construct(
        public ImpersonationSession $session,
        public ExtensionGrant $grant,
    ) {}
}
