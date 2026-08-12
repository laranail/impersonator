<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Modes;

use Simtabi\Laranail\Impersonator\Core\Contracts\ModeEnforcer;
use Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;

/**
 * Everything the target can do — no narrowing at all.
 *
 * Note this still allows strictly less than "no impersonation package": the
 * target's own permissions apply, the audit trail records every request, and the
 * kill switch still reaches the session. `full` means the mode adds no further
 * constraint, not that nothing is enforced.
 */
final readonly class FullModeEnforcer implements ModeEnforcer
{
    public function mode(): string
    {
        return Mode::FULL;
    }

    public function check(AttemptedAction $action, ImpersonationSession $session): Decision
    {
        return Decision::allow();
    }

    public function guardsPersistence(): bool
    {
        return false;
    }

    public function describe(): string
    {
        return 'Full access — everything the impersonated user can do.';
    }
}
