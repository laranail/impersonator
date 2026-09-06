<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Actions;

use Psr\Clock\ClockInterface;
use Illuminate\Contracts\Events\Dispatcher;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalDenied;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalGranted;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalDecision;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Laravel\Support\ReviewerDirectory;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ApprovalNotDecidable;

/**
 * A second operator answers a break-glass request: yes or no.
 *
 * Both answers run the same guards, because both are decisions of record. Three of them, in
 * order:
 *
 *  1. **The approver holds the approve permission.** A distinct permission from `enter`: the
 *     person who authorises access and the person who uses it are different roles, and an
 *     install that conflated them would have no four-eyes control at all.
 *  2. **The approver is not the requester.** Enforced here rather than assumed of the UI. A
 *     flow where one pair of eyes can be both pairs is a delay, not a control.
 *  3. **The request still accepts decisions and has not expired.** Pending *or* partially approved:
 *     a chain short of quorum is still open, and refusing a second reviewer there would make a
 *     multi-reviewer policy unsatisfiable. The store's locked recount is what actually settles this
 *     under concurrency; the check here is what produces a clear error instead of a bare null.
 *  4. **The reviewer fills an outstanding role slot, and passes the application's own rule.** Only
 *     when a policy names roles or an eligibility rule is registered — the ordinary single-reviewer
 *     flow reaches neither.
 *
 * What this deliberately does *not* do is start the impersonation. Granting authorises the
 * requester to enter, once, from their own session — so the audit trail records the operator
 * who did the work rather than the one who permitted it.
 */
final readonly class DecideApproval
{
    public function __construct(
        private ApprovalStore $approvals,
        private AuthorizationPolicy $policy,
        private ClockInterface $clock,
        private Dispatcher $events,
        private ReviewerDirectory $reviewers,
        private IdentityResolver $identities,
    ) {}

    /** @throws ImpersonationDenied|ApprovalNotDecidable */
    public function grant(string $approvalId, Identity $approver, ?string $note = null): ApprovalRequest
    {
        $request = $this->guard($approvalId, $approver);

        $granted = $this->approvals->grant($approvalId, $approver, $note, $this->slotFor($request, $approver))
            ?? throw ApprovalNotDecidable::alreadyDecided($approvalId);

        $this->events->dispatch(new ApprovalGranted($approvalId, $granted->request, $approver));

        return $granted;
    }

    /**
     * @throws ImpersonationDenied|ApprovalNotDecidable
     *
     * A denial takes no slot. It is terminal whoever recorded it, so which role they would have filled
     * is a question with no consequence — and recording one would imply the slot was satisfied.
     */
    public function deny(string $approvalId, Identity $approver, ?string $note = null): ApprovalRequest
    {
        $this->guard($approvalId, $approver);

        $denied = $this->approvals->deny($approvalId, $approver, $note)
            ?? throw ApprovalNotDecidable::alreadyDecided($approvalId);

        $this->events->dispatch(new ApprovalDenied($approvalId, $approver, $note));

        return $denied;
    }

    /**
     * The role slot this approval fills, or null when the policy names none.
     *
     * Picked from the outstanding slots this reviewer actually holds, and **one only** — a person who
     * is both a manager and an auditor fills one of them, which is the rule that makes role slots
     * mean anything. Which one is settled now and never recomputed: reading it from live roles later
     * would let a role change retroactively satisfy a policy for a request already decided.
     *
     * @throws ApprovalNotDecidable when the policy needs roles and this reviewer holds none outstanding
     */
    private function slotFor(ApprovalRequest $request, Identity $approver): ?string
    {
        $policy = $this->approvals->policyFor($request);

        if ($policy->roles === []) {
            return null;
        }

        $reviewer = $this->identities->resolveActor($approver);

        if ($reviewer === null) {
            throw ApprovalNotDecidable::missing($request->id);
        }

        $held = $this->reviewers->rolesFor($reviewer, array_keys($policy->roles));
        $slots = $policy->slotsFor($held, $this->approvedDecisions($request->id));

        if ($slots === []) {
            // Either they hold none of the required roles, or every slot they could fill is taken. Both
            // mean this approval would not advance the chain, and recording it anyway would let three
            // managers satisfy a policy that asked for an auditor.
            throw ImpersonationDenied::from(Decision::deny(
                Decision::APPROVER_NOT_ELIGIBLE,
                'You do not hold a role this request is still waiting on.',
                ['detail' => 'role', 'required' => implode(', ', array_keys($policy->roles))],
            ));
        }

        return $slots[0];
    }

    /** @return list<ApprovalDecision> */
    private function approvedDecisions(string $approvalId): array
    {
        return array_values(array_filter(
            $this->approvals->decisions($approvalId),
            static fn (object $decision): bool => $decision->approved(),
        ));
    }

    /**
     * Throw unless this operator may decide this request, right now.
     *
     * Returns nothing on purpose. The row it read is deliberately *not* handed to the caller,
     * because acting on it would mean acting on a snapshot taken before the decision — and the
     * store's conditional update is what actually settles the transition under concurrency. The
     * caller uses the row the update returns instead.
     *
     * @throws ImpersonationDenied|ApprovalNotDecidable
     */
    private function guard(string $approvalId, Identity $approver): ApprovalRequest
    {
        $decision = $this->policy->authorizeApproval($approver);

        if ($decision->denied()) {
            throw ImpersonationDenied::from($decision);
        }

        $request = $this->approvals->find($approvalId) ?? throw ApprovalNotDecidable::missing($approvalId);

        // Before anything else about roles or quorum. The requester is excluded however many roles
        // they hold — a four-eyes flow where one pair of eyes can be both pairs is a delay, not a
        // control, and no amount of privilege gets past it.
        if ($request->requester->is($approver)) {
            throw ApprovalNotDecidable::selfApproval($approvalId);
        }

        // Pending *or* partially approved. Refusing a second reviewer on a chain short of quorum would
        // make a multi-reviewer policy unsatisfiable.
        if (! $request->state->acceptsDecisions()) {
            throw ApprovalNotDecidable::alreadyDecided($approvalId);
        }

        if ($request->hasExpired($this->clock->now())) {
            throw ApprovalNotDecidable::expired($approvalId);
        }

        $reviewer = $this->identities->resolveActor($approver);

        if ($reviewer !== null && ! $this->reviewers->isEligible($reviewer, $request)) {
            // The application's own rule refused — "must be the requester's line manager", or whatever
            // relationship this package has no business modelling. Fails closed on anything but true.
            throw ImpersonationDenied::from(Decision::deny(
                Decision::APPROVER_NOT_ELIGIBLE,
                'You are not eligible to decide this request.',
                ['detail' => 'rule'],
            ));
        }

        return $request;
    }
}
