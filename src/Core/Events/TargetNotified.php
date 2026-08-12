<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * The target was told their account had been accessed.
 *
 * Emitted after the notification is dispatched, so a compliance report can evidence
 * that disclosure happened rather than only that it was configured.
 */
final readonly class TargetNotified
{
    public function __construct(
        public ImpersonationSession $session,
        public string $channel,
    ) {}
}
