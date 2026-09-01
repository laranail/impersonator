<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Adapters;

use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthAdapter;
use Simtabi\Laranail\Impersonator\Core\Enums\CredentialType;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;
use Simtabi\Laranail\Impersonator\Core\Values\Credential;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Throwable;

/**
 * Impersonation for Passport-authenticated APIs.
 *
 * Passport is OAuth2, so the honest framing is that this issues an access token on the
 * target's behalf with an impersonation scope — not a password-grant login, and deliberately
 * **never a refresh token**. A refresh token would let an impersonation renew itself
 * indefinitely, outliving both its audit row and the operator's authority to hold it, which
 * defeats the point of a short-lived support credential.
 *
 * The token carries the audit id as a scope-adjacent marker and is created through Passport's
 * own `createToken`, so it appears in `oauth_access_tokens` like any other and an
 * application's existing token tooling can see it.
 *
 * Revocation is immediate and by token id: Passport marks the row revoked, and its own guard
 * refuses it on the next request without any help from this package.
 */
final readonly class PassportAdapter implements AuthAdapter
{
    public function __construct(
        private IdentityResolver $identities,
        private Settings $settings,
    ) {}

    public function name(): string
    {
        return 'passport';
    }

    public function isAvailable(): bool
    {
        return class_exists(Passport::class) && class_exists(Token::class);
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

        // Passport's own contract for a token-bearing user, so `createToken` is verifiable
        // rather than probed for.
        if (! $target instanceof OAuthenticatable) {
            throw new ImpersonationException(sprintf(
                '%s cannot be impersonated with the passport adapter: it does not implement %s, '
                .'so no access token can be issued for it.',
                $target::class,
                OAuthenticatable::class,
            ));
        }

        // Passport validates scopes against its registered list and rejects anything unknown,
        // so the one scope this package needs is declared before issuing. Merged rather than
        // set, so an application's own scopes are untouched — and skipped entirely when the
        // app has already declared it, which is the documented way to control its description.
        $this->ensureScopeRegistered();

        $expiresAt = now()->addMinutes($this->tokenLifetime());

        // Passport's own issuance path, so the token lands in `oauth_access_tokens` and the
        // application's existing tooling sees it like any other.
        //
        // The two setup requirements Passport imposes are surfaced by name here, because its
        // own exceptions ("Invalid key supplied", "Personal access client not found") give an
        // operator no indication that impersonation is what needs configuring.
        try {
            $issued = $target->createToken(
                name: 'impersonation:'.$session->auditId,
                scopes: [$this->scope()],
            );
        } catch (Throwable $failure) {
            throw new ImpersonationException('Passport could not issue an impersonation token. It needs an encryption keypair '
            .'(`php artisan passport:keys`), a personal access client '
            .'(`php artisan passport:client --personal`), and a guard whose driver is '
            .'`passport` for the target\'s provider. Underlying error: '
            .$failure->getMessage(), $failure->getCode(), previous: $failure);
        }

        // `getToken()` rather than a property: Passport 13's result object exposes the model
        // through an accessor, and reading `->token` returns null via its `__get`.
        $accessToken = $issued->getToken();

        if (! $accessToken instanceof Token) {
            throw new ImpersonationException('Passport did not return an access token record.');
        }

        // Shortened after issuance because Passport's TTL is configured globally at boot;
        // writing the expiry here keeps the impersonation credential short-lived without
        // shortening every other token the application issues.
        $accessToken->forceFill(['expires_at' => $expiresAt])->save();

        return Credential::bearer(
            type: CredentialType::PassportToken,
            // Returned once. Passport does not store the plaintext either — only the audit
            // row's SHA-256 digest and this response ever hold it.
            secret: $this->requirePlaintext($issued->accessToken),
            reference: is_scalar($key = $accessToken->getKey()) ? (string) $key : null,
            expiresAt: $expiresAt->toDateTimeImmutable(),
            metadata: [
                'scope' => $this->scope(),
                'audit_id' => $session->auditId,
                // Stated explicitly so it is visible in the audit metadata rather than
                // being an unstated property of the implementation.
                'refresh_token' => false,
            ],
        );
    }

    public function release(ImpersonationSession $session): void
    {
        $this->revokeToken($session);
    }

    /**
     * Revocation is immediate: Passport marks the row revoked and its own guard refuses the
     * token on the next request, with no help from this package.
     */
    public function revoke(ImpersonationSession $session): bool
    {
        return $this->revokeToken($session);
    }

    private function revokeToken(ImpersonationSession $session): bool
    {
        try {
            $reference = $session->metadata['credential_reference'] ?? null;

            $query = Token::query();

            if (is_string($reference) && $reference !== '') {
                $query->whereKey($reference);
            } else {
                $query->where('name', 'impersonation:'.$session->auditId);
            }

            // Marked revoked rather than deleted, so the OAuth record of the grant survives
            // for audit while the credential stops working.
            return $query->where('revoked', false)->update(['revoked' => true]) > 0;
        } catch (Throwable) {
            // Passport's tables may not be migrated. False is correct: the audit row is
            // still marked and the middleware still refuses on our own routes.
            return false;
        }
    }

    /**
     * The plaintext, insisted upon — the result object's accessor is untyped, and a null would
     * mean an audit row for a credential nobody received.
     */
    private function requirePlaintext(mixed $plaintext): string
    {
        if (! is_string($plaintext) || $plaintext === '') {
            throw new ImpersonationException('Passport returned no plaintext token for the impersonation.');
        }

        return $plaintext;
    }

    /**
     * Declare the impersonation scope with Passport if it is not already known.
     *
     * Not invasive despite touching global state: the scope name belongs to this package, the
     * merge preserves everything the application registered, and without it the adapter cannot
     * issue a token at all — Passport rejects unknown scopes outright.
     */
    private function ensureScopeRegistered(): void
    {
        $scope = $this->scope();
        $existing = [];

        foreach (Passport::scopes() as $registered) {
            $id = $registered->id ?? null;

            if (is_string($id)) {
                $existing[$id] = is_string($registered->description ?? null)
                    ? $registered->description
                    : $id;
            }
        }

        if (array_key_exists($scope, $existing)) {
            return;
        }

        Passport::tokensCan($existing + [
            $scope => 'Act on this account as a support operator, for the duration of an impersonation',
        ]);
    }

    private function scope(): string
    {
        return $this->settings->string('adapters.passport.scope', 'impersonated');
    }

    private function tokenLifetime(): int
    {
        return max(1, $this->settings->int('adapters.passport.expires_after', 15));
    }
}
