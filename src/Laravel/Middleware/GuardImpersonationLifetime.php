<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Middleware;

use Closure;
use DateTimeImmutable;
use Illuminate\Http\Request;
use Psr\Clock\ClockInterface;
use Illuminate\Contracts\Session\Session;
use Symfony\Component\HttpFoundation\Response;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\RedirectGuard;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * Terminates an impersonation that has been revoked or has outlived `max_duration`.
 *
 * This is the half of the kill switch that actually pulls the trigger. An
 * administrator marks the audit row from anywhere — another session, an API call, a
 * console command — and this middleware ends the impersonation on the target
 * session's next request, because a session can only be terminated from inside
 * itself.
 *
 * The lookup that makes it viable is cached (see EloquentAuditStore), so enforcing
 * this costs a cache read per request rather than a query. That is the reason the
 * feature can exist at all: no other package in this space offers remote revocation,
 * and a database round trip on every request is why.
 *
 * Ordered before mode enforcement: there is no point judging what a terminated
 * session may do.
 */
final class GuardImpersonationLifetime
{
    /**
     * Memoised per-request answer to the re-authorization check.
     *
     * The class is no longer `readonly` for this one field. Middleware is resolved per request, so the
     * memo cannot outlive the request that set it — and a route that passes through this middleware
     * twice would otherwise pay for the permission lookup twice.
     */
    private ?bool $stillAuthorized = null;

    public function __construct(
        private readonly ImpersonationManager $impersonator,
        private readonly AuditStore $audits,
        private readonly RedirectGuard $redirects,
        private readonly ClockInterface $clock,
        private readonly Settings $settings,
        private readonly Session $session,
    ) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        $session = $this->impersonator->current();

        if ($session === null) {
            return $next($request);
        }

        $now = $this->clock->now();

        // Session state is the operator's own copy and cannot be trusted to know
        // about a revocation recorded elsewhere, so the durable row is consulted.
        // Falling back to the session copy keeps the expiry check working even if
        // the row has been pruned.
        $authoritative = $this->audits->find($session->auditId) ?? $session;

        $reason = match (true) {
            $authoritative->isRevoked()                                    => EndReason::Revoked,
            $authoritative->isExpiredAt($now), $session->isExpiredAt($now) => EndReason::Expired,
            $this->hasGoneIdle($now)                                       => EndReason::Expired,
            $this->hasLostAuthorization($session)                          => EndReason::Revoked,
            default                                                        => null,
        };

        if ($reason === null) {
            $this->touch($now);

            return $next($request);
        }

        $this->impersonator->leave($reason);

        return $this->terminated($request, $reason);
    }

    /**
     * Whether the impersonation has sat idle past `limits.max_idle`.
     *
     * Separate from `max_duration`, which is absolute. An impersonation abandoned mid-session is
     * exactly the row that turns up in an audit with no explanation, and an absolute cap alone leaves
     * it open for the full hour — an idle cap closes the tab nobody came back to.
     *
     * Off by default: an idle cap that surprises an operator mid-investigation is worse than none, so
     * this is a choice an installation makes.
     */
    private function hasGoneIdle(DateTimeImmutable $now): bool
    {
        $idle = $this->settings->positiveIntOrNull('limits.max_idle');

        if ($idle === null) {
            return false;
        }

        $lastSeen = $this->session->get($this->activityKey());

        // No stamp yet means this is the first request of the impersonation, not an idle one. Treating
        // an absent value as infinitely old would terminate every impersonation on its second request.
        if (! is_numeric($lastSeen)) {
            return false;
        }

        return ($now->getTimestamp() - (int) $lastSeen) > $idle * 60;
    }

    /**
     * Record that the operator is still working, so the idle clock restarts.
     *
     * Written on every surviving request rather than on a schedule: the session is the only place a
     * per-request timestamp is free, and a database write per request to track idleness would cost more
     * than the feature is worth.
     */
    private function touch(DateTimeImmutable $now): void
    {
        if ($this->settings->positiveIntOrNull('limits.max_idle') !== null) {
            $this->session->put($this->activityKey(), $now->getTimestamp());
        }
    }

    private function activityKey(): string
    {
        return $this->settings->string('session.key', 'impersonator') . '_last_activity';
    }

    /**
     * Whether the operator still holds the permission they entered with.
     *
     * The policy runs at enter; without this, revoking an operator's role leaves their live sessions
     * running until the duration cap — so the withdrawal that mattered most takes effect last. Checked
     * against the mode, which under RBAC tests the coarse entry permission first.
     *
     * **Config-gated and cached per request.** It costs a permission lookup per request, which on an
     * RBAC package that hits the database is not free; and it is memoised so a route passing through
     * this middleware twice pays once.
     */
    private function hasLostAuthorization(ImpersonationSession $session): bool
    {
        if (! $this->settings->bool('authorization.recheck_each_request', false)) {
            return false;
        }

        $this->stillAuthorized ??= $this->impersonator
            ->policy()
            ->authorizeMode($session->impersonator, $session->mode->name)
            ->allowed;

        return $this->stillAuthorized === false;
    }

    /**
     * Ends the request rather than continuing it.
     *
     * Continuing would serve one more request as the target after access was
     * withdrawn, which is exactly what a kill switch exists to prevent — so this is
     * a redirect or a 403, never a pass-through.
     */
    private function terminated(Request $request, EndReason $reason): Response
    {
        $message = $reason === EndReason::Revoked
            ? 'This impersonation was ended by an administrator.'
            : 'This impersonation has expired.';

        if ($request->expectsJson()) {
            return response()->json([
                'message'  => $message,
                'ended_by' => $reason->value,
            ], 403);
        }

        return redirect()
            ->to($this->redirects->afterLeave())
            ->with('impersonator_status', $message);
    }
}
