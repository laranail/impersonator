<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Psr\Clock\ClockInterface;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalDenied;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalGranted;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ApprovalNotDecidable;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;

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
 *  3. **The request is still pending and unexpired.** The store's conditional update is what
 *     actually settles this under concurrency; the check here is what produces a clear error
 *     instead of a bare null.
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
    ) {}

    /** @throws ImpersonationDenied|ApprovalNotDecidable */
    public function grant(string $approvalId, Identity $approver, ?string $note = null): ApprovalRequest
    {
        $this->guard($approvalId, $approver);

        $granted = $this->approvals->grant($approvalId, $approver, $note)
            ?? throw ApprovalNotDecidable::alreadyDecided($approvalId);

        $this->events->dispatch(new ApprovalGranted($approvalId, $granted->request, $approver));

        return $granted;
    }

    /** @throws ImpersonationDenied|ApprovalNotDecidable */
    public function deny(string $approvalId, Identity $approver, ?string $note = null): ApprovalRequest
    {
        $this->guard($approvalId, $approver);

        $denied = $this->approvals->deny($approvalId, $approver, $note)
            ?? throw ApprovalNotDecidable::alreadyDecided($approvalId);

        $this->events->dispatch(new ApprovalDenied($approvalId, $approver, $note));

        return $denied;
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
    private function guard(string $approvalId, Identity $approver): void
    {
        $decision = $this->policy->authorizeApproval($approver);

        if ($decision->denied()) {
            throw ImpersonationDenied::from($decision);
        }

        $request = $this->approvals->find($approvalId) ?? throw ApprovalNotDecidable::missing($approvalId);

        if ($request->requester->is($approver)) {
            throw ApprovalNotDecidable::selfApproval($approvalId);
        }

        if (! $request->pending()) {
            throw ApprovalNotDecidable::alreadyDecided($approvalId);
        }

        if ($request->hasExpired($this->clock->now())) {
            throw ApprovalNotDecidable::expired($approvalId);
        }
    }
}
