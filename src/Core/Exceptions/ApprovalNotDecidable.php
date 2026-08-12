<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Exceptions;

/**
 * A break-glass request cannot be decided as asked.
 *
 * Unlike a token rejection, these reasons are safe to distinguish for the caller: an approver
 * is an authorised operator acting on a request they were shown, so telling them it was
 * already answered is useful rather than a hint to somebody probing. The `reason()` code is
 * what the API surfaces and what the log records.
 */
final class ApprovalNotDecidable extends ImpersonationException
{
    private function __construct(
        private readonly string $reason,
        string $message,
        public readonly string $approvalId,
    ) {
        parent::__construct($message);
    }

    public static function missing(string $approvalId): self
    {
        return new self('unknown', 'That approval request does not exist.', $approvalId);
    }

    public static function alreadyDecided(string $approvalId): self
    {
        return new self(
            'already_decided',
            'That approval request has already been decided.',
            $approvalId,
        );
    }

    public static function expired(string $approvalId): self
    {
        return new self(
            'expired',
            'That approval request expired before it was decided.',
            $approvalId,
        );
    }

    public static function selfApproval(string $approvalId): self
    {
        return new self(
            'self_approval',
            'You cannot approve your own impersonation request.',
            $approvalId,
        );
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
