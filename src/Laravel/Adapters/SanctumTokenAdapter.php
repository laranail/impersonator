<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Adapters;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\Sanctum;
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
 * Impersonation for Sanctum-authenticated APIs.
 *
 * For an API there is no session to switch, so impersonation means something different and
 * the docs say it plainly: **a short-lived credential is issued for the target**, scoped to
 * impersonation, returned exactly once, and never retrievable again.
 *
 * Four properties make that safe rather than just convenient:
 *
 *  - **One ability: `impersonated`.** Not `*`. The token cannot do everything the target's
 *    own tokens can, and an application can check for that ability to refuse anything it
 *    considers off-limits to an impersonated caller.
 *  - **A short expiry**, independent of the app's own Sanctum expiration, because a
 *    support credential and a user's own API token have nothing in common lifetime-wise.
 *  - **The audit id is in the token's name**, so a leaked or misused token traces back to
 *    the operator who caused it. That back-reference is the difference between "somebody's
 *    token did this" and an accountable record.
 *  - **Only the digest is kept.** Sanctum already stores a hash rather than the plaintext,
 *    and the audit row keeps its own SHA-256 — the plaintext exists in one response and
 *    nowhere else.
 *
 * The token is written through Sanctum's own model rather than the target's `createToken()`, so
 * the target needs neither the `HasApiTokens` trait nor its contract. See `authenticate()`.
 *
 * Revocation deletes the token row, so unlike a session this takes effect immediately and
 * everywhere, with no next-request dependency.
 */
final readonly class SanctumTokenAdapter implements AuthAdapter
{
    public function __construct(
        private IdentityResolver $identities,
        private Settings $settings,
    ) {}

    public function name(): string
    {
        return 'sanctum';
    }

    public function isAvailable(): bool
    {
        // The model rather than the service provider: a token cannot be issued without it,
        // and it is the class every path here actually touches.
        return class_exists(PersonalAccessToken::class);
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

        $expiresAt = now()->addMinutes($this->tokenLifetime());
        $plaintext = $this->generateTokenString();

        // Written through Sanctum's own token model rather than the target's `createToken()`.
        //
        // That is deliberate and it matters: Sanctum's `HasApiTokens` trait carries no
        // `@phpstan-require-implements`, and Laravel's default `User` uses the trait *without*
        // implementing the contract — so requiring either would refuse the most common setup in
        // existence. Going through the model instead means any Eloquent target works, the call
        // is fully typed, and `Sanctum::$personalAccessTokenModel` is still honoured.
        $model = Sanctum::personalAccessTokenModel();

        /** @var Model $accessToken */
        $accessToken = new $model;

        $accessToken->forceFill([
            'tokenable_type' => $target->getMorphClass(),
            'tokenable_id' => $target->getKey(),
            // The audit id in the name is the back-reference. Sanctum names are not unique, so
            // this is a label rather than a key — but it is the label a human reads when asking
            // which impersonation a token belongs to.
            'name' => 'impersonation:' . $session->auditId,
            'token' => hash('sha256', $plaintext),
            'abilities' => [$this->ability()],
            'expires_at' => $expiresAt,
        ])->save();

        $this->recordMetadata($accessToken, $session);

        return Credential::bearer(
            type: CredentialType::SanctumToken,
            // Sanctum's wire format is `{id}|{plaintext}`, which its own guard splits on. The
            // one and only copy: returned to the caller, hashed for the audit row, never stored.
            secret: $this->keyOf($accessToken) . '|' . $plaintext,
            reference: $this->keyOf($accessToken),
            expiresAt: $expiresAt->toDateTimeImmutable(),
            metadata: [
                'ability' => $this->ability(),
                'audit_id' => $session->auditId,
            ],
        );
    }

    /**
     * Sanctum's token string: an optional configured prefix, 40 random characters, and a CRC of
     * them. Reproduced rather than borrowed because `generateTokenString()` lives on the trait,
     * which is exactly the dependency this adapter avoids.
     */
    private function generateTokenString(): string
    {
        $entropy = Str::random(40);
        $prefix = config('sanctum.token_prefix', '');

        return (is_string($prefix) ? $prefix : '') . $entropy . hash('crc32b', $entropy);
    }

    /**
     * Leaving deletes the issued token.
     *
     * Idempotent and silent on a missing row: leave only ever de-escalates, so a token that
     * has already expired or been revoked elsewhere must not turn leaving into an error.
     */
    public function release(ImpersonationSession $session): void
    {
        $this->deleteToken($session);
    }

    /**
     * Revocation deletes the token too — and here it takes effect immediately, unlike a
     * session, which can only be ended from inside itself.
     */
    public function revoke(ImpersonationSession $session): bool
    {
        return $this->deleteToken($session);
    }

    private function deleteToken(ImpersonationSession $session): bool
    {
        try {
            $query = PersonalAccessToken::query();

            // Prefer the stored token id; fall back to the audit-id label, which covers a
            // row written before the credential was attached.
            $reference = $session->metadata['credential_reference'] ?? null;

            if (is_string($reference) && $reference !== '') {
                return $query->whereKey($reference)->delete() > 0;
            }

            return $query->where('name', 'impersonation:' . $session->auditId)->delete() > 0;
        } catch (Throwable) {
            // Sanctum's table may not exist, or the connection may be gone. Reporting false
            // is correct: the audit row is still marked and the middleware still refuses.
            return false;
        }
    }

    /**
     * Store the audit link on the token row when Sanctum's model can carry it.
     *
     * Written through `forceFill` on a nullable column an application may not have, so this
     * is best-effort by design — the authoritative link lives on the audit row.
     */
    private function recordMetadata(Model $token, ImpersonationSession $session): void
    {
        try {
            if (! in_array('impersonation_audit_id', $token->getConnection()
                ->getSchemaBuilder()
                ->getColumnListing($token->getTable()), true)) {
                return;
            }

            $token->forceFill(['impersonation_audit_id' => $session->auditId])->save();
        } catch (Throwable) {
            // A schema probe is not worth failing an impersonation over.
        }
    }

    /** The token row's primary key as a string. */
    private function keyOf(Model $token): string
    {
        $key = $token->getKey();

        if (! is_scalar($key)) {
            throw new ImpersonationException('The Sanctum token row has no usable primary key.');
        }

        return (string) $key;
    }

    private function ability(): string
    {
        return $this->settings->string('adapters.sanctum.ability', 'impersonated');
    }

    /**
     * Minutes the credential lives.
     *
     * Deliberately its own setting rather than Sanctum's `expiration`: a support credential
     * and a user's own long-lived API token have nothing in common, and inheriting the app's
     * value would routinely produce an impersonation token valid for weeks.
     */
    private function tokenLifetime(): int
    {
        return max(1, $this->settings->int('adapters.sanctum.expires_after', 15));
    }
}
