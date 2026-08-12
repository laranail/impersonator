<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Contracts;

use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * How the impersonator reaches the target's context — the other orthogonal axis.
 *
 * A driver answers "where does this happen": in the current application
 * (SessionDriver), across a domain boundary via a single-use token
 * (TokenDriver), or through a tenancy package's own handoff (TenancyDriver).
 * It delegates the question of what authentication means to an AuthAdapter.
 *
 * Drivers run after authorization has passed and are responsible for the
 * ordering that makes the audit trail trustworthy: open the audit row, then
 * authenticate, never the reverse.
 */
interface ImpersonationDriver
{
    /** The config name this driver registers under, e.g. `token`. */
    public function name(): string;

    /**
     * Whether this driver can run in the current installation — its optional
     * package is present, its table exists, its prerequisites are configured.
     */
    public function isAvailable(): bool;

    /**
     * Begin an impersonation.
     *
     * Returns an outcome rather than a session because drivers do not all
     * finish in one request: a same-app driver has the target authenticated by
     * the time this returns, while a cross-domain driver has only produced a
     * URL the operator must still follow. Collapsing both into "a session" is
     * what makes cross-domain impersonation look complete when it has not yet
     * happened.
     */
    public function begin(ImpersonationRequest $request): ImpersonationOutcome;

    /**
     * Complete a handoff a previous `begin()` only started, by redeeming the
     * single-use token it issued.
     *
     * Drivers that finish within `begin()` throw
     * `Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException`
     * here; `requiresHandoff()` tells callers which kind they hold.
     */
    public function complete(string $token): ImpersonationOutcome;

    /** Whether `begin()` returns a pending handoff that `complete()` must finish. */
    public function requiresHandoff(): bool;

    /**
     * End the impersonation, restoring the impersonator.
     *
     * Always available to the impersonated session and only ever
     * de-escalating — there is no failure mode in which a caller is left as the
     * target because leaving errored.
     */
    public function end(ImpersonationSession $session, EndReason $reason = EndReason::Left): void;

    /**
     * The impersonation active in the current context, or null.
     *
     * Read from server-side state only. A driver that reconstructed this from a
     * request parameter or header would hand clients the ability to declare
     * their own mode, which is the escalation this package exists to prevent.
     */
    public function current(): ?ImpersonationSession;
}
