<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use DateTimeImmutable;
use DateTimeInterface;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalState;

/**
 * A break-glass approval: one operator asking a second one to authorise an impersonation.
 *
 * Read model over a row in `impersonator_approval_requests`. Nothing here is trusted from
 * client input — the requester, target and mode are recorded when the request is opened and
 * are what the permit is later checked against.
 *
 * **An approval is a one-time permit bound to a fingerprint**, not a general blessing. The
 * fingerprint covers the requester, the target and the mode, which is what stops the three
 * ways an approval could otherwise be widened after the fact: a permit for `read_only`
 * being spent on `full`, a permit for one customer being spent on another, and a permit
 * granted to one operator being spent by a colleague. Everything a permit does *not* bind
 * to is deliberate too — see {@see fingerprintFor()}.
 */
final readonly class ApprovalRequest
{
    public function __construct(
        public string $id,
        public Identity $requester,
        public Identity $target,
        public Mode $mode,
        public ImpersonationRequest $request,
        public ApprovalState $state,
        public DateTimeImmutable $expiresAt,
        public ?string $reason = null,
        public ?Identity $decidedBy = null,
        public ?string $decisionNote = null,
        public ?DateTimeImmutable $decidedAt = null,
        public ?string $auditId = null,
        public ?DateTimeImmutable $createdAt = null,
    ) {}

    /**
     * The identity of a permit: who asked, about whom, at what level of access.
     *
     * Bound to exactly those three things. It is **not** bound to the reason text, because an
     * operator fixing a typo in their justification should not need a second approval; nor to
     * the IP or user agent, because an operator who requested from a laptop and returns on a
     * phone has not done anything suspicious, and binding to those would produce refusals
     * whose cause is invisible. Nor to the driver or guard, which are the application's
     * configuration rather than the operator's choice.
     *
     * Hashed rather than stored as a readable tuple so the value can be compared, indexed and
     * logged without a target's id appearing in a log line as a side effect.
     */
    public static function fingerprintFor(Identity $requester, Identity $target, string $mode): string
    {
        // Unit-separated, so a requester id ending in a colon cannot be made to collide with
        // a different target by moving the boundary between the two fields.
        return hash('sha256', implode("\x1f", [$requester->key(), $target->key(), $mode]));
    }

    public function fingerprint(): string
    {
        return self::fingerprintFor($this->requester, $this->target, $this->mode->name);
    }

    public function pending(): bool
    {
        return $this->state === ApprovalState::Pending;
    }

    public function approved(): bool
    {
        return $this->state === ApprovalState::Approved;
    }

    public function consumed(): bool
    {
        return $this->state === ApprovalState::Consumed;
    }

    /**
     * Whether the TTL has elapsed, regardless of what the stored state says.
     *
     * The state column is only as fresh as the last write, so a row can read `pending` long
     * after it stopped being usable. Callers must ask this rather than trusting the column:
     * a sweeper that marks rows expired is a convenience for the approver queue, never the
     * thing that decides whether a permit still works.
     */
    public function hasExpired(DateTimeInterface $now): bool
    {
        return $this->expiresAt <= DateTimeImmutable::createFromInterface($now);
    }

    /** Whether this permit can still be spent by this operator, right now. */
    public function usableBy(Identity $operator, DateTimeInterface $now): bool
    {
        return $this->approved()
            && ! $this->hasExpired($now)
            && $this->requester->is($operator);
    }

    /**
     * Whether this operator may decide this request.
     *
     * The requester is excluded here rather than only in the action, because "you cannot
     * approve your own request" is the entire point of the control — a four-eyes flow where
     * one pair of eyes can be both pairs is not a flow, it is a delay.
     */
    public function decidableBy(Identity $operator, DateTimeInterface $now): bool
    {
        return $this->pending()
            && ! $this->hasExpired($now)
            && $this->requester->isNot($operator);
    }

    public function withState(ApprovalState $state): self
    {
        return new self(
            $this->id,
            $this->requester,
            $this->target,
            $this->mode,
            $this->request,
            $state,
            $this->expiresAt,
            $this->reason,
            $this->decidedBy,
            $this->decisionNote,
            $this->decidedAt,
            $this->auditId,
            $this->createdAt,
        );
    }

    /**
     * The safe projection.
     *
     * Carries no credential and no session id, because an approval queue is a screen several
     * operators can see — including ones who hold the approve permission but not the enter
     * permission, and who therefore have no business holding anything spendable.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'requester' => $this->requester->toArray(),
            'target' => $this->target->toArray(),
            'mode' => $this->mode->name,
            'state' => $this->state->value,
            'reason' => $this->reason,
            'decided_by' => $this->decidedBy?->toArray(),
            'decision_note' => $this->decisionNote,
            'decided_at' => $this->decidedAt?->format(DATE_ATOM),
            'audit_id' => $this->auditId,
            'expires_at' => $this->expiresAt->format(DATE_ATOM),
            'created_at' => $this->createdAt?->format(DATE_ATOM),
        ];
    }
}
