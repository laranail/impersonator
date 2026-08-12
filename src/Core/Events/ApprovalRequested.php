<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;

/**
 * An impersonation needs a second authorized operator before it can start.
 *
 * The break-glass flow. Nobody is impersonating anything at this point — the
 * request is pending, and a listener that provisioned access here would defeat the
 * whole purpose of requiring approval.
 */
final readonly class ApprovalRequested
{
    public function __construct(
        public string $approvalId,
        public ImpersonationRequest $request,
    ) {}
}
