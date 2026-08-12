<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Psr\Clock\ClockInterface;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\RedirectGuard;
use Symfony\Component\HttpFoundation\Response;

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
final readonly class GuardImpersonationLifetime
{
    public function __construct(
        private ImpersonationManager $impersonator,
        private AuditStore $audits,
        private RedirectGuard $redirects,
        private ClockInterface $clock,
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
            $authoritative->isRevoked() => EndReason::Revoked,
            $authoritative->isExpiredAt($now), $session->isExpiredAt($now) => EndReason::Expired,
            default => null,
        };

        if ($reason === null) {
            return $next($request);
        }

        $this->impersonator->leave($reason);

        return $this->terminated($request, $reason);
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
                'message' => $message,
                'ended_by' => $reason->value,
            ], 403);
        }

        return redirect()
            ->to($this->redirects->afterLeave())
            ->with('impersonator_status', $message);
    }
}
