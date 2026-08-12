<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalState;

/**
 * How many reviewers a request needs, and in which roles.
 *
 * Pure and framework-free: primitives in, a state or a count out. The whole reason a chain's rules
 * are expressible as a value object is that they are arithmetic over recorded decisions — no clock,
 * no container, no database.
 *
 * ### The four semantics, each chosen rather than fallen into
 *
 * **A single denial is terminal.** Approvals accumulate; a refusal ends the request immediately.
 * Failing closed is the only safe reading of a disagreement about access to somebody's account, and
 * it means a reviewer who spots a problem does not have to persuade the others first.
 *
 * **One reviewer fills at most one role slot.** Otherwise a person holding both `manager` and
 * `auditor` satisfies a two-role policy alone, and the separation of duties is theatre. This is the
 * rule that makes role slots mean anything at all.
 *
 * **The effective requirement is `max(quorum, sum(roles))`.** So `quorum` is an independent floor
 * rather than something a role map silently overrides: a policy asking for three reviewers of whom
 * one must be an auditor needs three, not one.
 *
 * **Unfilled roles are what is outstanding.** A count alone cannot express "two of three, still
 * needs an auditor", and that sentence is the useful thing to show a queue.
 */
final readonly class ApprovalPolicy
{
    /**
     * @param int $quorum how many approvals are needed at minimum
     * @param array<string, int> $roles role slug => how many approvals must come from that role
     */
    public function __construct(
        public int $quorum = 1,
        public array $roles = [],
    ) {}

    /**
     * @param array<string, mixed> $config a `policies.{mode}` entry
     */
    public static function fromArray(array $config): self
    {
        $quorum = $config['quorum'] ?? 1;
        $roles = $config['roles'] ?? [];

        $slots = [];

        if (is_array($roles)) {
            foreach ($roles as $role => $count) {
                if (is_string($role) && $role !== '' && is_numeric($count) && (int) $count > 0) {
                    $slots[$role] = (int) $count;
                }
            }
        }

        return new self(
            // Floored at one: a zero quorum with no roles would mean "approval required" and
            // "nothing required" at once, and the request would be born already satisfied.
            quorum: max(1, is_numeric($quorum) ? (int) $quorum : 1),
            roles: $slots,
        );
    }

    /** How many approvals this policy needs in total. */
    public function required(): int
    {
        return max($this->quorum, array_sum($this->roles));
    }

    /** Whether this is the ordinary single-reviewer flow, needing no chain bookkeeping. */
    public function isSingleReviewer(): bool
    {
        return $this->required() === 1 && $this->roles === [];
    }

    /**
     * The state a request is in, given every decision recorded against it.
     *
     * The single place the chain's outcome is computed, so the store, the API and a queue screen
     * cannot disagree about whether a request is satisfied.
     *
     * @param list<ApprovalDecision> $decisions
     */
    public function stateFor(array $decisions): ApprovalState
    {
        foreach ($decisions as $decision) {
            if ($decision->denied()) {
                return ApprovalState::Denied;
            }
        }

        $approvals = array_values(array_filter($decisions, static fn (ApprovalDecision $d): bool => $d->approved()));

        if ($approvals === []) {
            return ApprovalState::Pending;
        }

        return $this->satisfiedBy($approvals)
            ? ApprovalState::Approved
            : ApprovalState::PartiallyApproved;
    }

    /**
     * Whether these approvals meet the policy.
     *
     * Both tests must pass: enough approvals in total, and every role slot filled. Checking only the
     * count would let three managers satisfy a policy that asked for an auditor.
     *
     * @param list<ApprovalDecision> $approvals
     */
    public function satisfiedBy(array $approvals): bool
    {
        return count($approvals) >= $this->required() && $this->outstandingRoles($approvals) === [];
    }

    /**
     * Role slots still unfilled.
     *
     * @param list<ApprovalDecision> $approvals
     * @return array<string, int> role => how many more are needed
     */
    public function outstandingRoles(array $approvals): array
    {
        $filled = [];

        foreach ($approvals as $approval) {
            // One slot per reviewer, enforced by only counting the slot their decision was recorded
            // against. A reviewer holding two required roles filled one of them.
            if ($approval->role !== null) {
                $filled[$approval->role] = ($filled[$approval->role] ?? 0) + 1;
            }
        }

        $outstanding = [];

        foreach ($this->roles as $role => $needed) {
            $short = $needed - ($filled[$role] ?? 0);

            if ($short > 0) {
                $outstanding[$role] = $short;
            }
        }

        return $outstanding;
    }

    /**
     * How many more approvals are needed, ignoring roles.
     *
     * @param list<ApprovalDecision> $approvals
     */
    public function outstandingCount(array $approvals): int
    {
        return max(0, $this->required() - count($approvals));
    }

    /**
     * Which role slots this reviewer could fill, given what is outstanding.
     *
     * Returns an empty list when the policy names no roles — every reviewer is then interchangeable
     * and a decision is recorded with a null slot.
     *
     * @param list<string> $reviewerRoles the roles this operator actually holds
     * @param list<ApprovalDecision> $approvals
     * @return list<string>
     */
    public function slotsFor(array $reviewerRoles, array $approvals): array
    {
        if ($this->roles === []) {
            return [];
        }

        $outstanding = $this->outstandingRoles($approvals);

        return array_values(array_filter(
            $reviewerRoles,
            static fn (string $role): bool => isset($outstanding[$role]),
        ));
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'quorum' => $this->quorum,
            'roles' => $this->roles,
            'required' => $this->required(),
        ];
    }
}
