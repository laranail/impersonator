<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Actions;

use Psr\Clock\ClockInterface;
use Illuminate\Contracts\Events\Dispatcher;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Values\ExtensionGrant;
use Simtabi\Laranail\Impersonator\Core\Values\ExtensionPolicy;
use Simtabi\Laranail\Impersonator\Core\Values\ExtensionOutcome;
use Simtabi\Laranail\Impersonator\Laravel\Support\SessionState;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationExtended;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;

/**
 * Keep a live impersonation running past its original deadline.
 *
 * Three gates, in this order, and the order is the design:
 *
 *  1. **The operator must still be permitted to impersonate at all.** Extending is not a
 *     de-escalation the way leaving is — it is a request for *more* access — so the entry
 *     permission is re-checked rather than assumed from the fact that a session exists. An
 *     operator whose role was withdrawn mid-session can finish what they are doing and
 *     leave; they cannot buy another window.
 *  2. **The caps, inside the store's locked transaction.** Never here: a check performed in
 *     this action would be a read the store's write does not hold a lock across, which is
 *     the race two clicks on one button actually produce.
 *  3. **The session copy is rewritten.** The lifetime middleware terminates on *either* the
 *     durable row or the session's own copy of the expiry, so leaving the copy stale would
 *     expire the impersonation the operator just extended.
 */
final readonly class ExtendImpersonation
{
    public function __construct(
        private AuditStore $audits,
        private AuthorizationPolicy $policy,
        private SessionState $state,
        private Dispatcher $events,
        private ClockInterface $clock,
    ) {}

    public function __invoke(ImpersonationSession $session, ExtensionPolicy $policy): ExtensionOutcome
    {
        $permitted = $this->policy->authorizeMode($session->impersonator, $session->mode->name);

        if ($permitted->denied()) {
            return new ExtensionOutcome($session, ExtensionGrant::refuse($permitted));
        }

        $outcome = $this->audits->extend($session->auditId, $policy, $this->clock->now());
        $extended = $outcome->session;

        // The bundled stores either find the row or throw, so a granted outcome always carries
        // one. Checked rather than assumed because AuditStore is a published contract a host
        // application may implement: a third-party store returning a sessionless grant should
        // fall through to a refusal, not skip the state rewrite and leave the operator with a
        // session copy that expires at the old time.
        if ($outcome->denied() || $extended === null) {
            return $outcome;
        }

        // Only when the extended row belongs to *this* request's session. The driver may not
        // be session-backed at all, and a token-driven impersonation has no session copy to
        // keep in step.
        if ($this->state->get()?->auditId === $extended->auditId) {
            $this->state->put($extended);
        }

        $this->events->dispatch(new ImpersonationExtended($extended, $outcome->grant));

        return $outcome;
    }
}
