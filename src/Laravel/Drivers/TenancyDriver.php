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
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;
use Simtabi\Laranail\Impersonator\Core\Exceptions\TokenRejected;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Support\SessionState;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Simtabi\Laranail\Impersonator\Laravel\Tokens\AcceptUrlBuilder;
use Simtabi\Laranail\Impersonator\Laravel\Tokens\EloquentTokenRepository;
use Stancl\Tenancy\Tenancy;

/**
 * Impersonation across a tenant boundary, for stancl/tenancy installations.
 *
 * Registered only when stancl is installed, and never a requirement — tenancy is one driver
 * among several, which is the whole point of having a driver axis.
 *
 * **Why this does not call `UserImpersonation::makeResponse()`.** stancl ships its own
 * impersonation feature, and wrapping it was the obvious approach until you read it. It stores
 * the token id *unhashed* as the primary key of a central table, checks single-use by deleting
 * the row after a non-atomic read, and redeems through `Auth::guard()->loginUsingId()` — which
 * means no session regeneration, no silent login, no audit row and no mode. It also
 * `abort(403)`s on a bad token, so a replay is indistinguishable from a typo in the logs.
 *
 * Every one of those is something this package exists to provide, and several are outright
 * regressions against the token driver already here. So this driver reuses the *token driver's*
 * machinery — 40 bytes of CSPRNG stored as a digest, claimed by a single atomic UPDATE — and
 * adds the two things tenancy actually needs:
 *
 *  1. **A tenant is required to enter.** A handoff URL has to address a specific tenant, and
 *     guessing produces a link to the wrong host.
 *  2. **The tenant is verified on redemption.** A token minted for one tenant must not be
 *     redeemable on another, and the refusal is indistinguishable from an unknown token —
 *     saying "wrong tenant" would confirm the token is real and name a second tenant.
 *
 * An application already using stancl's own feature keeps working; it simply is not the path
 * this driver takes.
 */
final readonly class TenancyDriver implements ImpersonationDriver
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
        return 'tenancy';
    }

    public function isAvailable(): bool
    {
        return class_exists(Tenancy::class) && $this->adapter->isAvailable();
    }

    public function requiresHandoff(): bool
    {
        return true;
    }

    public function begin(ImpersonationRequest $request): ImpersonationOutcome
    {
        if ($request->tenantId === null) {
            throw new ImpersonationException(
                'The tenancy driver needs an initialized tenant to impersonate into. Initialize '
                .'tenancy first, or use the token driver for a cross-domain handoff that is not '
                .'tenant-scoped.',
            );
        }

        $session = $this->audits->open($request, expiresAt: $this->maxDurationFrom());

        $token = $this->tokens->issue($request, $this->settings->int('tokens.ttl', 60));

        // Links the token to the row, so revoking the impersonation kills a handoff still in
        // flight. The token table lives on the central connection for the same reason stancl's
        // does: a tenant database cannot be reached from the host issuing the link.
        if ($this->tokens instanceof EloquentTokenRepository) {
            $this->tokens->attachAudit($token->plaintext(), $session->auditId);
        }

        $this->events->dispatch(new HandoffTokenIssued($session));

        return ImpersonationOutcome::pending(
            session: $session,
            // The only place the plaintext appears. Only its digest reaches the database.
            acceptUrl: $this->urls->build($request, $token->plaintext()),
            redirectTo: $request->redirectTo,
        );
    }

    public function complete(string $token): ImpersonationOutcome
    {
        try {
            $request = $this->tokens->consume($token);
        } catch (TokenRejected $rejected) {
            $this->events->dispatch(new HandoffTokenRejected($rejected->reason(), $this->requestIp()));

            throw $rejected;
        }

        // The tenant check, and the reason this driver exists separately. Reported as `unknown`
        // rather than its own reason: naming a tenant mismatch would confirm the token is real
        // and disclose that another tenant exists.
        if (! $this->tenantMatches($request)) {
            $this->events->dispatch(new HandoffTokenRejected('tenant_mismatch', $this->requestIp()));

            throw TokenRejected::unknown();
        }

        $decision = $this->policy->authorize($request);

        if ($decision->denied()) {
            $this->events->dispatch(new ImpersonationRejected($request, $decision));

            throw ImpersonationDenied::from($decision);
        }

        $session = $this->audits->open($request, expiresAt: $this->maxDurationFrom());

        // Our adapter rather than stancl's `loginUsingId`: this is what regenerates the session,
        // refuses remember-me and keeps the target's own Login listeners from firing.
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
        try {
            $this->adapter->release($session);
        } finally {
            $this->state->forget();
            $this->state->flashEnded($reason);

            $this->tokens->revokeFor($session->auditId);

            $closed = $this->audits->close($session->auditId, $reason);

            $this->events->dispatch(new ImpersonationEnded($closed, $reason));
        }
    }

    public function current(): ?ImpersonationSession
    {
        return $this->state->get();
    }

    /**
     * Whether the token was minted for the tenant now being redeemed on.
     *
     * A token with no tenant is refused outright: `begin()` requires one, so its absence means
     * the token did not come from this driver.
     */
    private function tenantMatches(ImpersonationRequest $request): bool
    {
        if ($request->tenantId === null) {
            return false;
        }

        $tenant = function_exists('tenant') ? tenant() : null;

        if (! is_object($tenant) || ! method_exists($tenant, 'getTenantKey')) {
            return false;
        }

        $current = $tenant->getTenantKey();

        return is_scalar($current) && (string) $current === $request->tenantId;
    }

    private function maxDurationFrom(): ?DateTimeImmutable
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
