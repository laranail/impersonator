<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Exceptions;

use DateTimeImmutable;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;

/**
 * The impersonation needs a second operator's approval, and a pending request now exists.
 *
 * Deliberately **not** an {@see ImpersonationDenied}, and rendered as 202 rather than 403.
 * The operator did nothing wrong, the request passed every authorization rule, and something
 * was created as a result — a request that is now waiting on somebody. Reporting that as a
 * refusal would tell an operator to go ask for permissions they already hold.
 */
final class ApprovalRequired extends ImpersonationException
{
    private function __construct(
        public readonly string $approvalId,
        public readonly ImpersonationRequest $request,
        public readonly DateTimeImmutable $expiresAt,
    ) {
        parent::__construct('This impersonation requires approval from a second operator.');
    }

    public static function pending(
        string $approvalId,
        ImpersonationRequest $request,
        DateTimeImmutable $expiresAt,
    ): self {
        return new self($approvalId, $request, $expiresAt);
    }

    public function code(): string
    {
        return 'approval_required';
    }
}
