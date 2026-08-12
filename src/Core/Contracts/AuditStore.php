<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Contracts;

use DateTimeImmutable;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Values\Credential;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * The session-level record: one row per impersonation, in `impersonator_audits`.
 *
 * Append-only from the package's perspective. The only mutations the package
 * performs on an existing row are the terminal transitions — closing it, or
 * marking it revoked — and both are one-way. There is deliberately no `update`
 * or `delete`; retention pruning is a separate concern the bridge implements
 * through MassPrunable, not something reachable from this contract.
 *
 * Implementations back the kill switch, so `markRevoked` must be visible to
 * other processes immediately.
 */
interface AuditStore
{
    /**
     * Write the row that opens an impersonation and return the read model.
     *
     * The returned session's `auditId` becomes the correlation id for the trail,
     * the credential and every log line, so this must run before the target is
     * authenticated — if authentication succeeds but the audit write failed,
     * there is an unlogged impersonation, which is the one outcome that must be
     * impossible.
     */
    public function open(
        ImpersonationRequest $request,
        ?Credential $credential = null,
        ?DateTimeImmutable $expiresAt = null,
    ): ImpersonationSession;

    /**
     * Close an open row. Idempotent: calling it on an already-closed row must
     * not overwrite the original reason or timestamp, because a `left` arriving
     * after a `revoked` would erase the fact that an administrator intervened.
     */
    public function close(string $auditId, EndReason $reason, ?DateTimeImmutable $at = null): ImpersonationSession;

    /**
     * Attach the issued credential's audit-safe details to an open row.
     *
     * Separate from `open()` because adapters that mint a credential need the
     * audit id to embed in it first — the credential references the audit row,
     * and the row records the credential's hash.
     */
    public function attachCredential(string $auditId, Credential $credential): void;

    public function find(string $auditId): ?ImpersonationSession;

    /**
     * The open row for a stateful session id, or null. Used on every request by
     * the enforcement middleware, so implementations are expected to be cached;
     * the cache must be invalidated by `markRevoked` and `close`.
     */
    public function findActiveBySessionId(string $sessionId): ?ImpersonationSession;

    /** The open row whose issued credential matches this SHA-256 digest. */
    public function findActiveByCredentialHash(string $credentialHash): ?ImpersonationSession;

    /**
     * Flag a row for termination without needing the impersonator's session.
     *
     * This is the kill switch. It does not end the session itself — it records
     * the intent, and the next request in that session is refused by the
     * middleware, which then closes the row with `EndReason::Revoked`.
     */
    public function markRevoked(string $auditId, ?Identity $revokedBy = null, ?string $note = null): void;

    public function isRevoked(string $auditId): bool;

    /** @return list<ImpersonationSession> every open row for this impersonator */
    public function activeFor(Identity $impersonator): array;

    /** @return list<ImpersonationSession> every open row targeting this user, by any impersonator */
    public function activeTargeting(Identity $target): array;

    /** How many impersonations this operator currently has open. */
    public function countActiveFor(Identity $impersonator): int;

    /**
     * Reconcile rows whose backing session no longer exists, closing them as
     * `EndReason::SessionLost`. A row left open forever reads as an ongoing
     * breach, so something has to sweep the ones nobody will ever return to.
     *
     * @return int the number of rows closed
     */
    public function closeStale(DateTimeImmutable $olderThan): int;
}
