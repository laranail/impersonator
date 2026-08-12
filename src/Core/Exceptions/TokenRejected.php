<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Exceptions;

/**
 * A handoff token could not be redeemed.
 *
 * Every factory produces the same generic message on purpose: an attacker
 * probing the accept route must not learn from the response whether a token
 * was unknown, already spent, or merely expired. The distinguishing detail
 * lives in `reason()`, which goes to the audit log, never to the client.
 */
final class TokenRejected extends ImpersonationException
{
    private const string PUBLIC_MESSAGE = 'This impersonation link is no longer valid.';

    private function __construct(private readonly string $reason)
    {
        parent::__construct(self::PUBLIC_MESSAGE);
    }

    public static function unknown(): self
    {
        return new self('unknown');
    }

    public static function expired(): self
    {
        return new self('expired');
    }

    public static function alreadyUsed(): self
    {
        return new self('already_used');
    }

    public static function revoked(): self
    {
        return new self('revoked');
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
