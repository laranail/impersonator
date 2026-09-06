<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Contracts;

use Simtabi\Laranail\Impersonator\Core\Values\Token;
use Simtabi\Laranail\Impersonator\Core\Exceptions\TokenRejected;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;

/**
 * Storage for single-use handoff tokens, used by the TokenDriver to move an
 * impersonation across a domain boundary.
 *
 * Implementations must satisfy four properties, each of which has a failing-path
 * test in the suite:
 *
 *  1. The plaintext is generated from a CSPRNG at the configured byte length and
 *     is never persisted — only its SHA-256 digest is.
 *  2. Lookup is by digest, so a database leak yields no redeemable token.
 *  3. Redemption is atomic and single-use. Two concurrent requests presenting
 *     the same token must produce exactly one success; the loser gets
 *     `TokenRejected::alreadyUsed()`.
 *  4. An expired token is refused even if unused, and the failure is
 *     indistinguishable to the client from an unknown one.
 */
interface TokenRepository
{
    /**
     * Mint a token for a pending impersonation and persist its digest.
     *
     * The returned Token carries the plaintext; it is the only time that value
     * is obtainable. Callers put it straight into the accept URL and drop it.
     */
    public function issue(ImpersonationRequest $request, int $ttlSeconds): Token;

    /**
     * Atomically redeem a plaintext token, returning the request it stood for.
     *
     * Must mark the token spent in the same operation that reads it — a
     * read-then-write pair is a replay window under concurrency.
     *
     * @throws TokenRejected when the token is unknown, expired, already spent,
     *                       or belongs to an impersonation that was revoked
     *                       before the handoff completed.
     */
    public function consume(string $plaintext): ImpersonationRequest;

    /**
     * Whether a plaintext token is currently redeemable. Advisory only —
     * never gate a redemption on this, since the answer can change between the
     * check and the call. Used by the doctor command and diagnostics.
     */
    public function isRedeemable(string $plaintext): bool;

    /**
     * Invalidate every unspent token issued for the given audit row, so a
     * revocation also closes a handoff that is still in flight.
     *
     * @return int the number of tokens invalidated
     */
    public function revokeFor(string $auditId): int;

    /**
     * Delete spent and expired tokens. Backs the prune-tokens command; safe to
     * run concurrently with issuance.
     *
     * @return int the number of rows removed
     */
    public function pruneExpired(): int;
}
