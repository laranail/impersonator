<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;

/**
 * A second operator approved a pending impersonation.
 *
 * The approver is always someone other than the requester — a flow that let one
 * person approve their own request is not a control, so `approvedBy` is recorded to
 * make that auditable after the fact.
 */
final readonly class ApprovalGranted
{
    public function __construct(
        public string $approvalId,
        public ImpersonationRequest $request,
        public Identity $approvedBy,
    ) {}
}
