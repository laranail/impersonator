<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Drivers;

use DateTimeImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Psr\Clock\ClockInterface;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthAdapter;
use Simtabi\Laranail\Impersonator\Core\Contracts\ImpersonationDriver;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationEnded;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationStarted;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Support\SessionState;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * Impersonation inside a single application — nothing crosses a domain boundary,
 * so the target is authenticated within the request that asked for it.
 *
 * The ordering in `begin()` is the load-bearing part. The audit row is opened
 * *before* the adapter authenticates anyone, because the one outcome that must be
 * impossible is an impersonation that happened without a record of it. If the
 * audit write fails, nobody was impersonated; if authentication fails after it,
 * there is a row with no end — which a stale sweep later closes as
 * `session_lost`, and which is the failure mode you want, since it is visible.
 */
final readonly class SessionDriver implements ImpersonationDriver
{
    public function __construct(
        private AuditStore $audits,
        private AuthAdapter $adapter,
        private SessionState $state,
        private Settings $settings,
        private Dispatcher $events,
        private ClockInterface $clock,
    ) {}

    public function name(): string
    {
        return 'session';
    }

    public function isAvailable(): bool
    {
        return $this->adapter->isAvailable();
    }

    public function requiresHandoff(): bool
    {
        return false;
    }

    public function begin(ImpersonationRequest $request): ImpersonationOutcome
    {
        $session = $this->audits->open($request, expiresAt: $this->expiryFor());

        $credential = $this->adapter->authenticate($request, $session);

        $this->audits->attachCredential($session->auditId, $credential);

        // Re-read so the state written to the session carries the session id the
        // adapter settled on, rather than the null it held a moment ago.
        $session = $this->audits->find($session->auditId) ?? $session;

        $this->state->put($session);

        $this->events->dispatch(new ImpersonationStarted($session));

        return ImpersonationOutcome::started(
            session: $session,
            credential: $credential,
            redirectTo: $request->redirectTo,
        );
    }

    /**
     * Never applicable: this driver finishes within `begin()`, so there is no
     * outstanding handoff for a token to complete.
     */
    public function complete(string $token): ImpersonationOutcome
    {
        throw new ImpersonationException(
            'The session driver completes within begin() and has no handoff to redeem. '
            . 'Use the token driver for cross-domain impersonation.',
        );
    }

    public function end(ImpersonationSession $session, EndReason $reason = EndReason::Left): void
    {
        // The adapter runs first and its failure is not allowed to abort the rest:
        // leaving must always de-escalate, so a broken restore still results in the
        // audit row closed and the session state cleared rather than in a caller
        // stranded inside the target's account.
        try {
            $this->adapter->release($session);
        } finally {
            $this->state->forget();
            $this->state->flashEnded($reason);

            $closed = $this->audits->close($session->auditId, $reason);

            $this->events->dispatch(new ImpersonationEnded($closed, $reason));
        }
    }

    public function current(): ?ImpersonationSession
    {
        return $this->state->get();
    }

    /**
     * When this impersonation should be force-ended, from `limits.max_duration`.
     * Null means unlimited, which the doctor command warns about.
     */
    private function expiryFor(): ?DateTimeImmutable
    {
        $minutes = $this->settings->positiveIntOrNull('limits.max_duration');

        if ($minutes === null) {
            return null;
        }

        return $this->clock->now()->modify('+' . $minutes . ' minutes');
    }
}
