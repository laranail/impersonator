<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Actions;

use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\ImpersonationDriver;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * End the current impersonation.
 *
 * Unauthorized on purpose. Leaving only ever de-escalates, so requiring a permission
 * to stop would mean an operator whose access was revoked mid-session could be left
 * unable to get out of a customer's account — which is worse than the thing the
 * permission would be protecting.
 */
final readonly class LeaveImpersonation
{
    public function __construct(private AuditStore $audits) {}

    public function __invoke(
        ImpersonationSession $session,
        ImpersonationDriver $driver,
        EndReason $reason = EndReason::Left,
    ): ImpersonationSession {
        $driver->end($session, $reason);

        // Re-read rather than returning the snapshot taken before the close. The caller wants to
        // know *how* it ended — an API response with a null `ended_by` for a completed leave is a
        // response that contradicts itself.
        return $this->audits->find($session->auditId) ?? $session;
    }
}
