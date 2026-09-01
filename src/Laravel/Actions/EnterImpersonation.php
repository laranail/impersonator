<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Impersonator\Core\Contracts\ImpersonationDriver;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRejected;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRequested;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ApprovalRequired;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * Begin an impersonation: authorize, clear approval, then hand off to the driver.
 *
 * One action, one unit of work, injected dependencies only — which is what makes the
 * *whole* authorization decision testable without a request, a route or a session,
 * and what makes it impossible for a second entry point to grow its own copy of these
 * rules. Every path in (HTTP, API, CLI, the model trait) goes through here.
 *
 * The ordering is the contract: request event, authorize, approval, reject-or-begin.
 * Nothing mutates before the policy has passed, and the approval gate sits *after* the
 * policy rather than beside it — see {@see clearApproval()}.
 */
final readonly class EnterImpersonation
{
    public function __construct(
        private AuthorizationPolicy $policy,
        private Dispatcher $events,
        private ApprovalStore $approvals,
        private RequestApproval $requestApproval,
        private Settings $settings,
    ) {}

    /**
     * @throws ImpersonationDenied when any rule in the authorization stack refuses
     * @throws ApprovalRequired when a second operator must sign off first
     */
    public function __invoke(ImpersonationRequest $request, ImpersonationDriver $driver): ImpersonationOutcome
    {
        // Fires for refused attempts too: a listener counting attempts needs the true
        // rate, not only the successes.
        $this->events->dispatch(new ImpersonationRequested($request));

        $decision = $this->policy->authorize($request);

        if ($decision->denied()) {
            // Emitted before the throw so a refusal stays observable even when the
            // caller catches the exception and renders its own response.
            $this->events->dispatch(new ImpersonationRejected($request, $decision));

            throw ImpersonationDenied::from($decision);
        }

        $permit = $this->clearApproval($request);

        if ($permit !== null) {
            // The approval id travels with the impersonation so the audit row names the request
            // that authorised it. Without this, an auditor holding an impersonation has no way
            // back to the approval — and an approval nobody can tie to what it permitted is not
            // much of a record.
            $request = $request->withMetadata(['approval_id' => $permit->id]);
        }

        $outcome = $driver->begin($request);

        // Both directions of the link, written after the driver has produced a row. A failure
        // here would leave the impersonation running with a one-way link, which is why it is not
        // allowed to happen before the entry: the impersonation is the thing that matters, and
        // the approval already records everything except which row it became.
        if ($permit !== null) {
            $this->approvals->attachAudit($permit->id, $outcome->auditId());
        }

        return $outcome;
    }

    /**
     * Spend a permit, or open a request and stop.
     *
     * Runs after the policy, not alongside it. An operator who may not impersonate this
     * account at all must be refused outright rather than have their request put in front of
     * an approver — otherwise a refusal is converted into a queue entry that teaches them the
     * account exists, and invites an approver to grant something the policy will refuse a
     * second time anyway.
     *
     * Note the direction of the check: `consume()` spends the permit **now**, and the entry
     * proceeds on the strength of that single atomic write. Asking "is there an approval?" and
     * entering afterwards would be the read-then-write race that makes a one-time permit
     * reusable under two concurrent requests.
     *
     * @return ApprovalRequest|null the permit that was spent, or null when none was needed
     *
     * @throws ApprovalRequired
     */
    private function clearApproval(ImpersonationRequest $request): ?ApprovalRequest
    {
        if (! $this->requiresApproval($request)) {
            return null;
        }

        $permit = $this->approvals->consume(
            ApprovalRequest::fingerprintFor($request->impersonator, $request->target, $request->mode->name),
            $request->impersonator,
        );

        if ($permit !== null) {
            return $permit;
        }

        $opened = ($this->requestApproval)($request);

        throw ApprovalRequired::pending($opened->id, $request, $opened->expiresAt);
    }

    /**
     * Whether this particular request needs a second operator.
     *
     * Exempting modes is the point of the feature rather than a loophole: requiring a second
     * person for read-only support work trains everyone to approve reflexively, which is how a
     * four-eyes control becomes a rubber stamp. `read_only` is exempt by default and `full` is
     * not.
     */
    private function requiresApproval(ImpersonationRequest $request): bool
    {
        if (! $this->settings->bool('approval.require', false)) {
            return false;
        }

        return ! in_array(
            $request->mode->name,
            $this->settings->stringList('approval.except_modes'),
            strict: true,
        );
    }
}
