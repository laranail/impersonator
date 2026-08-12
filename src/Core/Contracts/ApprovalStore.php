<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Contracts;

use DateTimeImmutable;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalDecision;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalPolicy;
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
 *  - **`grant()` and `deny()` never re-decide a closed request.** An already-decided request must
 *    not be re-decided, or an approver who said no can be overruled by a later yes — or the
 *    same approval can be granted twice and spent twice.
 *  - **One decision per reviewer, enforced by the storage.** A guard in the calling code cannot
 *    close this: two requests from the same approver both read no prior decision and both write, so
 *    one reviewer counts twice toward quorum and a two-reviewer policy is satisfied by one person.
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
     * Record one reviewer's approval and roll the chain's state forward.
     *
     * Returns the request as it stands afterwards, which may be `PartiallyApproved` rather than
     * `Approved` — a chain short of quorum is not a permit, and a caller must read the state rather
     * than assume a non-null return means the requester may now enter.
     *
     * Returns null when the row is absent, is closed, has expired, or this reviewer has already
     * decided it. The caller has already verified the approver, so a null means the answer changed
     * underneath them.
     *
     * `$role` is the **slot** this decision fills, not the roles the reviewer holds. Settled here and
     * never recomputed, or a later role change would retroactively satisfy a policy for a request
     * already decided.
     */
    public function grant(string $id, Identity $approver, ?string $note = null, ?string $role = null): ?ApprovalRequest;

    /**
     * Record one reviewer's refusal, which closes the request.
     *
     * A single denial is terminal however many approvals precede it: failing closed is the only safe
     * reading of a disagreement about access to somebody's account, and it means a reviewer who spots
     * a problem does not have to persuade the others.
     */
    public function deny(string $id, Identity $approver, ?string $note = null, ?string $role = null): ?ApprovalRequest;

    /**
     * Every decision recorded against a request, oldest first.
     *
     * The audit answer to "who signed off". Ordered oldest first because the sequence is the
     * interesting part — which reviewer moved first, and how long the rest took.
     *
     * @return list<ApprovalDecision>
     */
    public function decisions(string $id): array;

    /**
     * The policy a request is judged against.
     *
     * Passed in rather than read by the store, so the quorum arithmetic stays in one pure place and
     * the store's job is confined to recording and recounting atomically.
     */
    public function policyFor(ApprovalRequest $request): ApprovalPolicy;

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
