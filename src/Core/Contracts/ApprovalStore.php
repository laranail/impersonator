<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Contracts;

use DateTimeImmutable;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;

/**
 * Where break-glass approvals live.
 *
 * The four-eyes control: an impersonation that needs a second authorised operator cannot
 * start until one says yes. This port keeps that flow out of the Core's way — the domain
 * knows an approval is required and that a permit is single-use; it does not know whether
 * the permits are rows, documents or an entry in somebody's ticket system.
 *
 * Two obligations any implementation must honour, because the security of the control rests
 * on them rather than on the calling code:
 *
 *  - **`consume()` is atomic.** Two requests spending the same permit simultaneously must
 *    produce exactly one success. A read-then-write is a race that both callers win, which
 *    turns a one-time permit into a two-time one.
 *  - **`grant()` and `deny()` transition only from pending.** An already-decided request must
 *    not be re-decided, or an approver who said no can be overruled by a later yes — or the
 *    same approval can be granted twice and spent twice.
 */
interface ApprovalStore
{
    /**
     * Record a new pending request and return it.
     *
     * The full impersonation request is stored alongside the fingerprint so the eventual
     * entry uses the parameters that were actually approved, rather than whatever the
     * requester submits on their way back.
     */
    public function open(ImpersonationRequest $request, DateTimeImmutable $expiresAt): ApprovalRequest;

    public function find(string $id): ?ApprovalRequest;

    /**
     * Approve a pending request.
     *
     * Returns null when the row is absent or no longer pending — the caller has already
     * verified the approver, so a null here means somebody else decided it first.
     */
    public function grant(string $id, Identity $approver, ?string $note = null): ?ApprovalRequest;

    /** Refuse a pending request. Returns null when it was not pending. */
    public function deny(string $id, Identity $approver, ?string $note = null): ?ApprovalRequest;

    /**
     * Spend the permit matching this fingerprint, atomically.
     *
     * Returns the consumed permit, or null when there is no unexpired approved permit for
     * that fingerprint. Callers treat null as "approval still required" rather than as an
     * error: a missing permit and a spent one are the same answer to the only question being
     * asked, which is whether this impersonation may proceed now.
     */
    public function consume(string $fingerprint, Identity $requester): ?ApprovalRequest;

    /**
     * The unexpired approved permit for this fingerprint, without spending it.
     *
     * For screens that want to show "your request was approved — you may now enter". Never
     * use this to authorise an entry: checking here and spending later is the race that
     * `consume()` exists to close.
     */
    public function findUsable(string $fingerprint, Identity $requester): ?ApprovalRequest;

    /**
     * Requests still awaiting a decision, newest first — the approver's queue.
     *
     * @return list<ApprovalRequest>
     */
    public function pending(int $limit = 50, int $offset = 0): array;

    /**
     * This operator's own requests, whatever their state, newest first.
     *
     * @return list<ApprovalRequest>
     */
    public function forRequester(Identity $requester, int $limit = 50, int $offset = 0): array;

    /** Attach the audit row an approval ultimately produced, closing the loop for auditors. */
    public function attachAudit(string $id, string $auditId): void;

    /**
     * Mark timed-out pending requests expired and return how many.
     *
     * Housekeeping for the approver queue, not a security boundary — expiry is enforced on
     * read, so a permit is dead at its TTL whether or not this has run.
     *
     * @return list<ApprovalRequest> the requests this call expired
     */
    public function expireStale(int $limit = 500): array;
}
