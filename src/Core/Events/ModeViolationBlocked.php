<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * The active mode refused something the impersonated session tried to do.
 *
 * The highest-signal event in the package. A read-only operator hitting a write
 * endpoint once is a misclick; the same operator hitting several in a row is
 * somebody testing the boundary, and that distinction only exists if each refusal
 * is observable.
 */
final readonly class ModeViolationBlocked
{
    public function __construct(
        public ImpersonationSession $session,
        public AttemptedAction $action,
        public Decision $decision,
    ) {}
}
