<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Psr\Clock\ClockInterface;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalRequested;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * Open a break-glass request: ask a second operator to authorise an impersonation.
 *
 * Reached only once the full authorization stack has already passed, which is the ordering
 * that matters. Opening a request first would mean an operator who may not impersonate that
 * account at all still gets to put it in front of an approver — teaching them that the
 * account exists, and inviting an approver to grant something the policy would refuse
 * anyway.
 */
final readonly class RequestApproval
{
    public function __construct(
        private ApprovalStore $approvals,
        private Settings $settings,
        private ClockInterface $clock,
        private Dispatcher $events,
    ) {}

    public function __invoke(ImpersonationRequest $request): ApprovalRequest
    {
        // An existing unspent permit is returned rather than a second row being opened. An
        // operator who resubmits after being told "awaiting approval" should see the same
        // request, not queue a duplicate for the approver to wade through.
        $existing = $this->approvals->findUsable(
            ApprovalRequest::fingerprintFor($request->impersonator, $request->target, $request->mode->name),
            $request->impersonator,
        );

        if ($existing !== null) {
            return $existing;
        }

        $ttl = max(1, $this->settings->int('approval.ttl', 15));

        $approval = $this->approvals->open(
            $request,
            $this->clock->now()->modify('+'.$ttl.' minutes'),
        );

        // Nobody is impersonating anything at this point. A listener that provisioned access
        // here would defeat the control it is listening to.
        $this->events->dispatch(new ApprovalRequested($approval->id, $request));

        return $approval;
    }
}
