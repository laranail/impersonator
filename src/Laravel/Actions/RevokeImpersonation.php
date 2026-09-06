<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthAdapter;
use Simtabi\Laranail\Impersonator\Core\Exceptions\AuditRowMissing;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRevoked;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;

/**
 * The kill switch: end somebody else's impersonation.
 *
 * Marks the audit row and, where the adapter can reach the credential, invalidates it
 * immediately. For session-backed impersonations there is nothing to reach into from
 * outside, so the mark is the mechanism — the target session's next request sees it
 * and terminates. That is why this returns without the session necessarily being over
 * yet, and why the middleware is the other half of the feature.
 */
final readonly class RevokeImpersonation
{
    public function __construct(
        private AuditStore $audits,
        private AuthorizationPolicy $policy,
        private Dispatcher $events,
    ) {}

    /** @throws ImpersonationDenied|AuditRowMissing */
    public function __invoke(
        string $auditId,
        ?Identity $revokedBy = null,
        ?string $note = null,
        ?AuthAdapter $adapter = null,
    ): ImpersonationSession {
        $session = $this->audits->find($auditId) ?? throw AuditRowMissing::for($auditId);

        if ($revokedBy !== null) {
            $decision = $this->policy->authorizeRevoke($revokedBy, $auditId);

            if ($decision->denied()) {
                throw ImpersonationDenied::from($decision);
            }
        }

        $this->audits->markRevoked($auditId, $revokedBy, $note);

        // Best effort, and only for adapters that hold a revocable credential. A
        // failure here must not stop the row being marked — the mark is what the
        // middleware acts on, so it is the part that has to survive.
        $adapter?->revoke($session);

        $revoked = $this->audits->find($auditId) ?? $session;

        $this->events->dispatch(new ImpersonationRevoked($revoked, $revokedBy, $note));

        return $revoked;
    }
}
