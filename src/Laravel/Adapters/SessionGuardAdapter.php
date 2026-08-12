<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Adapters;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Session\Session;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthAdapter;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;
use Simtabi\Laranail\Impersonator\Core\Values\Credential;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Laravel\Support\SessionTerminator;

/**
 * Authenticates the target on a stateful guard — the always-available adapter,
 * covering the standard `web` guard and Sanctum's SPA cookie mode alike, since
 * both are ordinary session guards underneath.
 *
 * Four behaviours here are security requirements rather than preferences:
 *
 *  - **The session id is regenerated on both enter and leave.** A session id that
 *    was valid at one privilege level must not still be valid at another, or a
 *    fixated id captured before the switch keeps working after it.
 *  - **Remember-me is never issued.** A remember cookie outlives the session, so
 *    an impersonation would silently resurrect itself on a later visit — long
 *    after its audit row was closed.
 *  - **`silent_login` authenticates without firing the app's Login listeners.**
 *    An impersonated login is not the target signing in; treating it as one sends
 *    them "new sign-in" mail and corrupts last-login columns.
 *  - **Leaving only de-escalates, and cannot fail into staying.** Every failure
 *    path in `release()` ends with the target logged out rather than with the
 *    caller stuck inside the account.
 */
final readonly class SessionGuardAdapter implements AuthAdapter
{
    public function __construct(
        private AuthFactory $auth,
        private Session $session,
        private Config $config,
        private IdentityResolver $identities,
        private SessionTerminator $terminator,
    ) {}

    public function name(): string
    {
        return 'session';
    }

    /**
     * Available whenever the configured target guard is stateful. A token guard
     * cannot be logged in, so pairing one with this adapter is a configuration
     * error worth surfacing at selection rather than at use.
     */
    public function isAvailable(): bool
    {
        try {
            return $this->auth->guard($this->targetGuardName()) instanceof StatefulGuard;
        } catch (\Throwable) {
            return false;
        }
    }

    public function authenticate(ImpersonationRequest $request, ImpersonationSession $session): Credential
    {
        $target = $this->identities->toUser(
            $request->target,
            withTrashed: (bool) $this->config->get('impersonator.targets.allow_soft_deleted', false),
        );

        if ($target === null) {
            throw new ImpersonationException(sprintf(
                'Cannot impersonate [%s]: the target could not be resolved. It may have been '
                . 'deleted, or its type may not be in the impersonator.targets.allowlist.',
                $request->target->key(),
            ));
        }

        // An allowlisted model that is not Authenticatable cannot be logged in at
        // all. Caught here rather than at the guard, which would fail with a type
        // error naming an Illuminate internal instead of the misconfiguration.
        if (! $target instanceof Authenticatable) {
            throw new ImpersonationException(sprintf(
                'Cannot impersonate [%s]: %s does not implement %s, so it cannot be '
                . 'authenticated on a guard.',
                $request->target->key(),
                $target::class,
                Authenticatable::class,
            ));
        }

        $guard = $this->statefulGuard($request->guards->target);

        // Before the switch, not after: regenerating afterwards would leave a
        // window in which the pre-impersonation id is authenticated as the target.
        $this->regenerate();

        $this->loginWithoutEvents($guard, $target);

        return Credential::session($this->session->getId());
    }

    public function release(ImpersonationSession $session): void
    {
        $guard = $this->statefulGuard($session->guards->target);

        if ($session->guards->areSame()) {
            // One guard for both sides, so logging the target in overwrote the
            // impersonator. Put them back.
            $impersonator = $this->identities->resolveActor($session->impersonator);

            if ($impersonator instanceof Authenticatable) {
                $this->regenerate();
                $this->loginWithoutEvents($guard, $impersonator);

                return;
            }

            // The impersonator's own account is gone. There is nobody to restore,
            // so the only safe outcome is nobody authenticated — never the target.
        }

        // Distinct guards: the impersonator was never displaced and is still
        // authenticated on their own guard, so dropping the target's guard is the
        // whole of leaving.
        $guard->logout();
        $this->regenerate();
    }

    /**
     * Destroy the impersonated session from outside it.
     *
     * True when the session record was actually removed, which is the difference between
     * revocation taking effect now and taking effect whenever the operator next loads a
     * page — potentially an hour later, which is the exact case revocation exists for.
     *
     * False for the drivers that hold no server-side record (`array`, `cookie`) and when
     * the audit row never captured a session id. Both fall back to the enforcement
     * middleware, so revocation is still correct — just not instant. That is why the
     * middleware exists as well as this rather than instead of it.
     */
    public function revoke(ImpersonationSession $session): bool
    {
        if ($session->sessionId === null) {
            return false;
        }

        return $this->terminator->terminate($session->sessionId);
    }

    /**
     * Authenticate without dispatching the framework's Login event.
     *
     * `Auth::login()` always fires it, so a silent login has to set the user and
     * write the guard's session key directly. That key is `$guard->getName()`,
     * which only SessionGuard exposes — any other stateful guard falls back to
     * the ordinary login, because guessing at another guard's session layout
     * would be a silent authentication failure.
     */
    private function loginWithoutEvents(StatefulGuard $guard, Authenticatable $user): void
    {
        $silent = (bool) $this->config->get('impersonator.session.silent_login', true);

        if (! $silent || ! $guard instanceof SessionGuard) {
            // `remember: false` is not a default being restated — it is the
            // requirement. See the class docblock.
            $guard->login($user, false);

            return;
        }

        $guard->setUser($user);
        $this->session->put($guard->getName(), $user->getAuthIdentifier());
    }

    /** Rotates the session id while preserving its data. */
    private function regenerate(): void
    {
        if ((bool) $this->config->get('impersonator.session.regenerate', true)) {
            $this->session->migrate(destroy: true);
        }
    }

    private function statefulGuard(string $name): StatefulGuard
    {
        $guard = $this->auth->guard($name);

        if (! $guard instanceof StatefulGuard) {
            throw new ImpersonationException(sprintf(
                'Guard [%s] is not stateful, so the session adapter cannot log a user in on it. '
                . 'Use an API adapter (sanctum, passport, jwt) for token guards.',
                $name,
            ));
        }

        return $guard;
    }

    private function targetGuardName(): string
    {
        $name = $this->config->get('impersonator.guards.target', 'web');

        return is_string($name) && $name !== '' ? $name : 'web';
    }
}
