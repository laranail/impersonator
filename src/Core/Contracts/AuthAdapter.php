<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Contracts;

use Simtabi\Laranail\Impersonator\Core\Values\Credential;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * How the target gets authenticated — one of the two orthogonal axes.
 *
 * An adapter answers "what does acting as this user consist of": mutating a
 * stateful session, or minting a scoped short-lived bearer credential. It is
 * paired freely with an ImpersonationDriver, which answers the separate
 * question of how the impersonator reaches the target's context.
 *
 * Adapters are trusted code running after the full authorization stack has
 * already passed. They must not re-decide authorization, and they must not be
 * reachable from a route.
 *
 * For the API adapters, impersonation means issuing a credential for the
 * target, scoped to impersonation, expiring shortly, and readable exactly once.
 */
interface AuthAdapter
{
    /** The config name this adapter registers under, e.g. `sanctum`. */
    public function name(): string;

    /**
     * Whether this adapter can run in the current installation. Returns false
     * when its optional package is absent or the named guard is not of a
     * compatible driver, which is what lets the service provider register every
     * adapter unconditionally and still fail loudly at selection rather than
     * mysteriously at use.
     */
    public function isAvailable(): bool;

    /**
     * Authenticate the target and return the resulting credential.
     *
     * Called with the audit row already open, so the returned credential can
     * embed `$session->auditId` — that back-reference is what makes a leaked
     * token traceable to the operator who caused it. Stateful implementations
     * regenerate the session id, refuse remember-me, and honour `silent_login`
     * so the app's own login listeners do not fire for an impersonated login.
     */
    public function authenticate(ImpersonationRequest $request, ImpersonationSession $session): Credential;

    /**
     * Undo `authenticate`, restoring the impersonator where the adapter is
     * stateful and revoking the issued credential where it is not.
     *
     * Must succeed even when the credential has already expired or been revoked
     * elsewhere: leave only ever de-escalates, so it can never be the operation
     * that leaves someone stuck as the target.
     */
    public function release(ImpersonationSession $session): void;

    /**
     * Invalidate a credential from outside its own session, for the kill switch.
     *
     * Distinct from `release()` because there is no session context here — the
     * adapter has only the audit row and must act on the stored reference or
     * hash. Session-based adapters report false, since a session can only be
     * ended by the middleware on that session's next request.
     *
     * @return bool whether the credential was actively invalidated
     */
    public function revoke(ImpersonationSession $session): bool;
}
