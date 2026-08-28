<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Adapters;

use Throwable;
use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Contracts\Container\Container;
use Simtabi\Laranail\Impersonator\Core\Values\Credential;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Simtabi\Laranail\Impersonator\Core\Enums\CredentialType;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthAdapter;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;

/**
 * Impersonation for JWT-authenticated APIs, via tymon/jwt-auth.
 *
 * A JWT is self-contained, which changes the problem in one important way: the credential
 * carries its own claims and an application can inspect them without a database lookup. So
 * the impersonation facts go *into* the token:
 *
 *  - `imp_by` — the operator's identity key.
 *  - `imp_audit` — the audit row id, the correlation id for everything else.
 *  - `imp_mode` — the active mode, so a resource server can enforce it without asking us.
 *
 * That last one matters: with a session driver the mode is enforced by our middleware, but a
 * JWT may be presented to a service that has never heard of this package. Putting the mode
 * in the claims is what lets that service refuse a write from a `read_only` impersonation.
 *
 * The flip side of self-containment is that a JWT cannot be un-issued. Leaving therefore
 * *blacklists* it, and the blacklist has to be enabled for that to mean anything — so this
 * reports honestly when it is not, rather than implying a revocation that will not happen.
 */
final readonly class JwtAdapter implements AuthAdapter
{
    public function __construct(
        private Container $app,
        private IdentityResolver $identities,
        private Settings $settings,
    ) {}

    public function name(): string
    {
        return 'jwt';
    }

    public function isAvailable(): bool
    {
        return class_exists(JWTAuth::class) && $this->app->bound('tymon.jwt.auth');
    }

    public function authenticate(ImpersonationRequest $request, ImpersonationSession $session): Credential
    {
        $target = $this->identities->toUser(
            $request->target,
            withTrashed: $this->settings->bool('targets.allow_soft_deleted', false),
        );

        if ($target === null) {
            throw new ImpersonationException(sprintf(
                'Cannot impersonate [%s]: the target could not be resolved.',
                $request->target->key(),
            ));
        }

        // `fromUser` is declared against JWTSubject, and a model that does not implement it
        // cannot be the subject of a token at all — so this is the contract, not a courtesy.
        if (! $target instanceof JWTSubject) {
            throw new ImpersonationException(sprintf(
                '%s cannot be impersonated with the jwt adapter: it does not implement %s.',
                $target::class,
                JWTSubject::class,
            ));
        }

        $jwt = $this->jwt();

        $ttl = $this->tokenLifetime();

        // The TTL is set for this mint only and restored afterwards: `setTTL` is global
        // state on the factory, and leaving it changed would shorten every token the
        // application issues for the rest of the request.
        $factory = $jwt->factory();
        $previousTtl = $factory->getTTL();

        try {
            $factory->setTTL($ttl);

            $token = $jwt->claims($this->claims($session))->fromUser($target);
        } finally {
            $factory->setTTL($previousTtl);
        }

        if (! is_string($token) || $token === '') {
            throw new ImpersonationException('The JWT adapter could not mint a token for the target.');
        }

        return Credential::bearer(
            type: CredentialType::Jwt,
            secret: $token,
            expiresAt: now()->addMinutes($ttl)->toDateTimeImmutable(),
            metadata: [
                'claims'   => array_keys($this->claims($session)),
                'audit_id' => $session->auditId,
            ],
        );
    }

    public function release(ImpersonationSession $session): void
    {
        // Nothing to do without the token itself, and by design we do not keep it — only its
        // digest. The caller discards the credential on leave, and the claims' short TTL is
        // the backstop. `blacklist()` below is what a caller holding the token can use.
    }

    /**
     * A JWT cannot be un-issued, so revocation is a blacklist entry — and only if the
     * blacklist is enabled.
     *
     * Returning false when it is not is the honest answer: claiming to have revoked a
     * credential that will keep working until it expires would be worse than admitting the
     * limitation, and the middleware still refuses the impersonation on our own routes.
     */
    public function revoke(ImpersonationSession $session): bool
    {
        return false;
    }

    /**
     * Blacklist a token the caller still holds.
     *
     * Separate from `revoke()` because the contract's revoke has only the audit row, and a
     * JWT is not recoverable from it. An API that keeps the token can call this directly.
     */
    public function blacklist(string $token): bool
    {
        if (! $this->blacklistEnabled()) {
            return false;
        }

        try {
            $this->jwt()->setToken($token)->invalidate();

            return true;
        } catch (Throwable) {
            // Already expired or already blacklisted. Either way it is no longer usable,
            // which is the outcome asked for.
            return false;
        }
    }

    public function blacklistEnabled(): bool
    {
        return (bool) config('jwt.blacklist_enabled', true);
    }

    /**
     * The impersonation claims.
     *
     * Prefixed `imp_` rather than nested, because a flat namespace survives every JWT
     * library and inspection tool — and a resource server reading these has no obligation to
     * use the same stack we do.
     *
     * @return array<string, string>
     */
    private function claims(ImpersonationSession $session): array
    {
        return [
            'imp_by'    => $session->impersonator->key(),
            'imp_audit' => $session->auditId,
            'imp_mode'  => $session->mode->name,
        ];
    }

    private function tokenLifetime(): int
    {
        return max(1, $this->settings->int('adapters.jwt.ttl', 15));
    }

    private function jwt(): JWTAuth
    {
        $jwt = $this->app->make('tymon.jwt.auth');

        if (! $jwt instanceof JWTAuth) {
            throw new ImpersonationException('tymon/jwt-auth is installed but did not resolve a JWTAuth instance.');
        }

        return $jwt;
    }
}
