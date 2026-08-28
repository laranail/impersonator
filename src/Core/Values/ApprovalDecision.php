<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use DateTimeImmutable;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalVerdict;

/**
 * One reviewer's answer, as a row in `impersonator_approval_decisions`.
 *
 * The chain's decisions moved off the request row and into a child table when a second reviewer
 * became possible. Three columns on the parent (`decided_by_*`, `decision_note`, `decided_at`) can
 * hold exactly one answer, so a two-reviewer policy would have overwritten the first with the
 * second — losing the fact that anybody else had looked, which is the only fact an audit of a
 * four-eyes control is actually about.
 *
 * `role` records which **slot** this decision filled, not what roles the reviewer holds. A person
 * who is both a manager and an auditor fills one slot, and which one is a decision made once when
 * their verdict is recorded — recomputing it later from live roles would let a role change
 * retroactively satisfy or unsatisfy a policy for a request already decided.
 */
final readonly class ApprovalDecision
{
    public function __construct(
        public Identity $reviewer,
        public ApprovalVerdict $verdict,
        public DateTimeImmutable $decidedAt,
        public ?string $role = null,
        public ?string $note = null,
        public ?string $id = null,
    ) {}

    public function approved(): bool
    {
        return $this->verdict === ApprovalVerdict::Approved;
    }

    public function denied(): bool
    {
        return $this->verdict === ApprovalVerdict::Denied;
    }

    /** Whether this decision came from the given operator, so a reviewer cannot be counted twice. */
    public function by(Identity $operator): bool
    {
        return $this->reviewer->is($operator);
    }

    /**
     * The safe projection.
     *
     * Carries the reviewer, the slot and the note — everything an auditor asking "who signed off"
     * needs. Never the request's fingerprint: that is the value a permit is matched on, and an
     * approval queue is a screen several operators can see.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id'         => $this->id,
            'reviewer'   => $this->reviewer->toArray(),
            'verdict'    => $this->verdict->value,
            'role'       => $this->role,
            'note'       => $this->note,
            'decided_at' => $this->decidedAt->format(DATE_ATOM),
        ];
    }
}
