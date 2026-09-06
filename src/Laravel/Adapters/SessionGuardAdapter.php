<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Adapters;

use Throwable;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as Config;
use Simtabi\Laranail\Impersonator\Core\Values\Credential;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthAdapter;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Laravel\Support\SessionTerminator;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;

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
        } catch (Throwable) {
            return false;
        }
    }

    public function authenticate(ImpersonationRequest $request, ImpersonationSession $session): Credential
    {
        $target = $this->identities->toUser(
            $request->target,
            withTrashed: (bool) $this->config->get('laranail.impersonator.targets.allow_soft_deleted', false),
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
        $this->resetSession($this->operatorGuardKey($request));

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
                $this->resetSession();
                $this->loginWithoutEvents($guard, $impersonator);

                return;
            }

            // The impersonator's own account is gone. There is nobody to restore,
            // so the only safe outcome is nobody authenticated — never the target.
        }

        // Distinct guards: the impersonator was never displaced and is still
        // authenticated on their own guard, so dropping the target's guard is the
        // whole of leaving.
        $this->dropGuard($guard);
        $this->resetSession($this->operatorGuardKey($session));
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
     * Stop the target's guard from being authenticated, without touching their account.
     *
     * Deliberately **not** `$guard->logout()`. `SessionGuard::logout()` calls
     * `cycleRememberToken()`, which writes a fresh `remember_token` to the *target's* user row —
     * so an operator merely finishing a support session would log the real customer out of every
     * device they own, and invalidate a recaller cookie the customer set weeks ago on a phone this
     * package has never seen. It also queues a forget-cookie for `remember_web_<hash>`, which is
     * the same cookie name the operator's own remember-me uses on a shared guard.
     *
     * Forgetting the guard's session key is the whole of what leaving requires: it is what
     * `logout()` does that is actually about this session, minus the two side effects that reach
     * outside it.
     */
    private function dropGuard(StatefulGuard $guard): void
    {
        if (! $guard instanceof SessionGuard) {
            // A guard whose session layout is not knowable. `logout()` is the only contract
            // available, and for a non-SessionGuard there is no remember-token rotation to worry
            // about.
            $guard->logout();

            return;
        }

        $this->session->forget($guard->getName());

        // The session key alone is not enough: `AuthManager` caches resolved guards and each holds
        // its user in memory, so `Auth::guard(...)->check()` would keep answering with the target
        // for the rest of the request even though the session no longer names them.
        //
        // `forgetUser()` on this one guard rather than `AuthManager::forgetGuards()`, which would
        // clear every guard including the operator's own. That matters because a user set with
        // `setUser()` was never written to the session at all — clearing its cache would leave the
        // operator unauthenticated with nothing to re-resolve from, which is the opposite of what
        // leaving should do.
        $guard->forgetUser();
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
        $silent = (bool) $this->config->get('laranail.impersonator.session.silent_login', true);

        if (! $silent || ! $guard instanceof SessionGuard) {
            // `remember: false` is not a default being restated — it is the
            // requirement. See the class docblock.
            $guard->login($user, false);
            $this->syncPasswordHash($guard, $user);

            return;
        }

        $guard->setUser($user);
        $this->session->put($guard->getName(), $user->getAuthIdentifier());
        $this->syncPasswordHash($guard, $user);
    }

    /**
     * Re-point Laravel's session-password sentinel at whoever is now authenticated.
     *
     * `AuthenticateSession` stores a hash of the authenticated user's password under
     * `password_hash_<default guard>` and compares it on every request. A mismatch is treated as a
     * stolen or stale session: it calls `logoutCurrentDevice()`, flushes the session and throws. So
     * switching the authenticated user without moving that sentinel means the *operator* gets logged
     * out of their own account on the next request — which is the mechanism behind several
     * long-standing bug reports against other impersonation packages.
     *
     * Note the key is keyed on `auth.defaults.guard`, not on the guard being used. That is the
     * framework's choice, not ours, and it is why a multi-guard impersonation is the case that breaks:
     * the sentinel and the user being compared can come from two different guards.
     *
     * Flushing the session on switch happens to mask this, because the middleware re-seeds the key
     * when it is absent — but `session.flush_on_switch` is a documented opt-out, so relying on it
     * would leave the bug live for anyone who turns it off. Hence writing it explicitly.
     */
    private function syncPasswordHash(StatefulGuard $guard, Authenticatable $user): void
    {
        $key = 'password_hash_' . $this->defaultGuardName();
        $password = $user->getAuthPassword();

        if (! is_string($password) || $password === '') {
            // A passwordless account — SSO-only, or a model that does not store one.
            // `AuthenticateSession` skips the comparison entirely for these, so the correct state is
            // no sentinel at all rather than a stale one belonging to somebody else.
            $this->session->forget($key);

            return;
        }

        if (method_exists($guard, 'hashPasswordForCookie')) {
            $password = $guard->hashPasswordForCookie($password);
        }

        $this->session->put($key, $password);
    }

    /**
     * The guard name Laravel keys its session-password sentinel on.
     *
     * Read from config rather than `AuthManager::getDefaultDriver()`, which is not on the
     * `Auth\Factory` contract this adapter depends on. It is the same value — that method returns
     * `config('auth.defaults.guard')` verbatim.
     */
    private function defaultGuardName(): string
    {
        $guard = $this->config->get('auth.defaults.guard');

        return is_string($guard) && $guard !== '' ? $guard : 'web';
    }

    /**
     * Rotate the session id **and** clear what was in it.
     *
     * Rotating alone is not enough, and this is the subtle half. `migrate()` gives a new id and
     * destroys the old server-side record, but it keeps `$attributes` — so everything the operator
     * had in their session travels into the impersonated one, and everything the target accumulates
     * travels back out on leave. A cart, a multi-step form, flashed data, a "last viewed" key: all
     * of it crosses the boundary in both directions. That is a cross-account data leak, not an
     * inconvenience, and it is the bug most implementations in this space still have.
     *
     * Order matters. The flush happens here, before the guard's session key is written, because
     * clearing afterwards would delete the key that was just written and log the user straight back
     * out.
     *
     * `regenerate(true)` rather than `invalidate()` for the rotation: both flush and migrate, but
     * only `regenerate()` also mints a fresh CSRF token, and reusing the pre-switch token across a
     * privilege change is the thing rotation is supposed to prevent.
     */
    private function resetSession(?string $preserveGuard = null): void
    {
        if (! (bool) $this->config->get('laranail.impersonator.session.regenerate', true)) {
            return;
        }

        if ((bool) $this->config->get('laranail.impersonator.session.flush_on_switch', true)) {
            // One exception to the flush, and it is not optional. When the operator sits on a
            // *different* guard than the target, they were never displaced and must stay logged in
            // — so their own auth key has to survive. Flushing it would log the operator out of
            // their own account as a side effect of impersonating somebody on another guard, and on
            // leave it would strand them with no session at all.
            $keep = $preserveGuard === null ? null : $this->session->get($preserveGuard);

            $this->session->flush();

            if ($preserveGuard !== null && $keep !== null) {
                $this->session->put($preserveGuard, $keep);
            }
        }

        $this->session->regenerate(destroy: true);
    }

    /**
     * The session key of the operator's own guard, when it differs from the target's.
     *
     * Null for a shared guard: there the operator's key is the one being overwritten, so there is
     * nothing to preserve and the correct value is written immediately afterwards.
     */
    private function operatorGuardKey(ImpersonationRequest|ImpersonationSession $context): ?string
    {
        $guards = $context->guards;

        if ($guards->areSame()) {
            return null;
        }

        $guard = $this->auth->guard($guards->impersonator);

        return $guard instanceof SessionGuard ? $guard->getName() : null;
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
        $name = $this->config->get('laranail.impersonator.guards.target', 'web');

        return is_string($name) && $name !== '' ? $name : 'web';
    }
}
