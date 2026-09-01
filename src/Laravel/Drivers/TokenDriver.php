<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Drivers;

use DateTimeImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Psr\Clock\ClockInterface;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthAdapter;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Impersonator\Core\Contracts\ImpersonationDriver;
use Simtabi\Laranail\Impersonator\Core\Contracts\TokenRepository;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Events\HandoffTokenIssued;
use Simtabi\Laranail\Impersonator\Core\Events\HandoffTokenRedeemed;
use Simtabi\Laranail\Impersonator\Core\Events\HandoffTokenRejected;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationEnded;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRejected;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationStarted;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Exceptions\TokenRejected;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Support\SessionState;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Simtabi\Laranail\Impersonator\Laravel\Tokens\AcceptUrlBuilder;
use Simtabi\Laranail\Impersonator\Laravel\Tokens\EloquentTokenRepository;

/**
 * Impersonation across a domain boundary, via a single-use token.
 *
 * The reason this driver exists is that a session cookie scoped to `admin.example.com`
 * does not reach `tenant.example.com`. So `begin()` cannot authenticate anybody — it mints
 * a token, opens the audit row, and hands back a URL. Nobody is impersonating anything
 * until that URL is followed, which is why the outcome is `pending` rather than `started`
 * and why `HandoffTokenIssued` is a different event from `ImpersonationStarted`.
 *
 * The security-critical decision is in `complete()`: **the authorization stack runs
 * again**. Not as belt-and-braces — as correctness. A permission can be withdrawn, a role
 * changed, the target soft-deleted or the audit row revoked in the seconds between minting
 * a link and following it, and a token that carried its own approval would still be
 * honoured. The token proves the request came from us; it does not prove it is still
 * allowed.
 */
final readonly class TokenDriver implements ImpersonationDriver
{
    public function __construct(
        private AuditStore $audits,
        private AuthAdapter $adapter,
        private TokenRepository $tokens,
        private AuthorizationPolicy $policy,
        private AcceptUrlBuilder $urls,
        private SessionState $state,
        private Settings $settings,
        private Dispatcher $events,
        private ClockInterface $clock,
    ) {}

    public function name(): string
    {
        return 'token';
    }

    public function isAvailable(): bool
    {
        return $this->adapter->isAvailable();
    }

    public function requiresHandoff(): bool
    {
        return true;
    }

    /**
     * Mint the token and return the URL that will complete the handoff.
     *
     * The audit row is opened here rather than at redemption, so an issued link that is
     * never followed still leaves a trace. A token minted for an account is worth knowing
     * about whether or not somebody walked through the door — and the row also gives
     * revocation something to act on before the handoff completes.
     */
    public function begin(ImpersonationRequest $request): ImpersonationOutcome
    {
        $session = $this->audits->open($request, expiresAt: $this->expiryFor());

        $token = $this->tokens->issue($request, $this->settings->int('tokens.ttl', 60));

        // Links the token to the row, so revoking the impersonation also kills a handoff
        // that is still in flight.
        if ($this->tokens instanceof EloquentTokenRepository) {
            $this->tokens->attachAudit($token->plaintext(), $session->auditId);
        }

        $this->events->dispatch(new HandoffTokenIssued($session));

        return ImpersonationOutcome::pending(
            session: $session,
            // The only place the plaintext appears. Not logged, not in the event, not
            // stored — the database holds its digest.
            acceptUrl: $this->urls->build($request, $token->plaintext()),
            redirectTo: $request->redirectTo,
        );
    }

    /**
     * Redeem a token and authenticate the target.
     *
     * Ordering matters: the token is consumed *before* authorization is re-checked. A
     * refused redemption still burns the token, because a token that survived a failed
     * attempt could be retried until the window happened to open — and the operator can
     * always be issued a fresh one.
     *
     * @throws TokenRejected when the token is unknown, expired, spent or revoked
     * @throws ImpersonationDenied when it is valid but no longer permitted
     */
    public function complete(string $token): ImpersonationOutcome
    {
        try {
            $request = $this->tokens->consume($token);
        } catch (TokenRejected $rejected) {
            // The reason reaches the log, never the client. Distinguishing expired from
            // unknown for a caller tells them the token was real.
            $this->events->dispatch(new HandoffTokenRejected($rejected->reason(), $this->requestIp()));

            throw $rejected;
        }

        $decision = $this->policy->authorize($request);

        if ($decision->denied()) {
            $this->events->dispatch(new ImpersonationRejected($request, $decision));

            throw ImpersonationDenied::from($decision);
        }

        // A fresh audit row: this one records the impersonation that actually happened, at
        // the moment it happened, on the host where it happened. The row from `begin()`
        // recorded that a link was issued, which is a different fact.
        $session = $this->audits->open($request, expiresAt: $this->expiryFor());

        $credential = $this->adapter->authenticate($request, $session);

        $this->audits->attachCredential($session->auditId, $credential);

        $session = $this->audits->find($session->auditId) ?? $session;

        $this->state->put($session);

        $this->events->dispatch(new HandoffTokenRedeemed($session));
        $this->events->dispatch(new ImpersonationStarted($session));

        return ImpersonationOutcome::started(
            session: $session,
            credential: $credential,
            redirectTo: $request->redirectTo,
        );
    }

    public function end(ImpersonationSession $session, EndReason $reason = EndReason::Left): void
    {
        // Identical to the session driver's ordering, and for the same reason: leaving must
        // always de-escalate, so a failed restore still closes the row and clears state
        // rather than stranding the caller inside the target's account.
        try {
            $this->adapter->release($session);
        } finally {
            $this->state->forget();
            $this->state->flashEnded($reason);

            // Any token still in flight for this impersonation is dead too.
            $this->tokens->revokeFor($session->auditId);

            $closed = $this->audits->close($session->auditId, $reason);

            $this->events->dispatch(new ImpersonationEnded($closed, $reason));
        }
    }

    public function current(): ?ImpersonationSession
    {
        return $this->state->get();
    }

    private function expiryFor(): ?DateTimeImmutable
    {
        $minutes = $this->settings->positiveIntOrNull('limits.max_duration');

        return $minutes === null
            ? null
            : $this->clock->now()->modify('+'.$minutes.' minutes');
    }

    private function requestIp(): ?string
    {
        return app()->bound('request') ? app('request')->ip() : null;
    }
}
