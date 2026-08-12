<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Tokens;

use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Str;
use Psr\Clock\ClockInterface;
use Simtabi\Laranail\Impersonator\Core\Contracts\TokenRepository;
use Simtabi\Laranail\Impersonator\Core\Exceptions\TokenRejected;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\Token;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Throwable;

/**
 * Single-use handoff tokens, in the database.
 *
 * Four properties matter, and each is a deliberate choice rather than a default:
 *
 *  - **The plaintext is never stored.** Only its SHA-256 digest, and lookups are *by* the
 *    digest — so a database leak yields nothing redeemable. A plain digest is right here
 *    rather than a password hash: the value is already 40 bytes of CSPRNG output, so
 *    there is nothing to brute-force and no reason to pay bcrypt on every redemption.
 *  - **Redemption is a single atomic UPDATE.** Not a read followed by a write: two
 *    requests presenting the same token concurrently would both pass a read-then-check
 *    and both be admitted, which is a replay window that only appears under load. Here
 *    the winner is whichever `UPDATE ... WHERE consumed_at IS NULL` touches a row, and the
 *    loser is told the token is spent.
 *  - **Every rejection looks the same to the client.** Unknown, expired, spent and revoked
 *    are distinguished only in `TokenRejected::reason()`, which goes to the audit log —
 *    because telling somebody probing the accept route that a token merely *expired* tells
 *    them it was real.
 *  - **The query builder, not Eloquent.** Model events, casts and a global scope have no
 *    business in the middle of an atomic claim, and `update()` returning an affected-row
 *    count is exactly what the claim needs.
 */
final readonly class EloquentTokenRepository implements TokenRepository
{
    public function __construct(
        private ConnectionResolverInterface $connections,
        private Settings $settings,
        private ClockInterface $clock,
    ) {}

    public function issue(ImpersonationRequest $request, int $ttlSeconds): Token
    {
        $plaintext = $this->generate();
        $expiresAt = $this->clock->now()->modify('+' . max(1, $ttlSeconds) . ' seconds');

        $this->table()->insert([
            'id' => strtolower((string) Str::ulid()),
            'token_hash' => $this->digest($plaintext),
            'audit_id' => null,
            'request' => json_encode($request->toArray(), JSON_THROW_ON_ERROR),
            'expires_at' => $expiresAt,
            'created_at' => $this->clock->now(),
            'updated_at' => $this->clock->now(),
        ]);

        return new Token($plaintext, $this->digest($plaintext), $expiresAt);
    }

    public function consume(string $plaintext): ImpersonationRequest
    {
        $digest = $this->digest($plaintext);
        $now = $this->clock->now();

        $row = $this->table()->where('token_hash', $digest)->first();

        // Unknown token. Same message as every other rejection.
        if ($row === null) {
            throw TokenRejected::unknown();
        }

        if ($row->revoked_at !== null) {
            throw TokenRejected::revoked();
        }

        if ($row->consumed_at !== null) {
            throw TokenRejected::alreadyUsed();
        }

        // Expiry is checked against the row rather than the parsed value object, because
        // this is the authoritative copy — and checked before the claim so an expired
        // token is not marked spent, which would make the audit trail read as a
        // successful redemption.
        if ($this->hasExpired($row->expires_at, $now)) {
            throw TokenRejected::expired();
        }

        // The claim. One statement, and the affected-row count is the arbitration: exactly
        // one concurrent caller can move `consumed_at` from null.
        $claimed = $this->table()
            ->where('token_hash', $digest)
            ->whereNull('consumed_at')
            ->whereNull('revoked_at')
            ->update(['consumed_at' => $now, 'updated_at' => $now]);

        if ($claimed !== 1) {
            throw TokenRejected::alreadyUsed();
        }

        return $this->decode($row->request);
    }

    public function isRedeemable(string $plaintext): bool
    {
        $row = $this->table()->where('token_hash', $this->digest($plaintext))->first();

        return $row !== null
            && $row->consumed_at === null
            && $row->revoked_at === null
            && ! $this->hasExpired($row->expires_at, $this->clock->now());
    }

    public function revokeFor(string $auditId): int
    {
        return $this->table()
            ->where('audit_id', $auditId)
            ->whereNull('consumed_at')
            ->whereNull('revoked_at')
            ->update(['revoked_at' => $this->clock->now(), 'updated_at' => $this->clock->now()]);
    }

    /** Attach the audit row, so revoking an impersonation also kills its in-flight token. */
    public function attachAudit(string $plaintext, string $auditId): void
    {
        $this->table()
            ->where('token_hash', $this->digest($plaintext))
            ->update(['audit_id' => $auditId, 'updated_at' => $this->clock->now()]);
    }

    public function pruneExpired(): int
    {
        $now = $this->clock->now();

        // Spent tokens go too, not only expired ones: a consumed token is no longer a
        // credential, and keeping it grows a hot table for no benefit — the audit row is
        // where the record of the handoff lives.
        return $this->table()
            ->where('expires_at', '<=', $now)
            ->orWhereNotNull('consumed_at')
            ->orWhereNotNull('revoked_at')
            ->delete();
    }

    /**
     * A fresh token.
     *
     * `random_bytes` rather than anything seedable, at the configured length with a 32-byte
     * floor — a token short enough to guess makes every other control here pointless.
     * Base64url-encoded so it survives a URL path segment without escaping.
     */
    private function generate(): string
    {
        $bytes = max(32, $this->settings->int('tokens.bytes', 40));

        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    private function digest(string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }

    private function hasExpired(mixed $expiresAt, \DateTimeImmutable $now): bool
    {
        if (! is_string($expiresAt) && ! $expiresAt instanceof \DateTimeInterface) {
            // An unreadable expiry is treated as expired. Failing closed here costs one
            // rejected handoff; failing open would hand out an unbounded token.
            return true;
        }

        try {
            $parsed = $expiresAt instanceof \DateTimeInterface
                ? \DateTimeImmutable::createFromInterface($expiresAt)
                : new \DateTimeImmutable($expiresAt);
        } catch (Throwable) {
            return true;
        }

        return $now > $parsed;
    }

    private function decode(mixed $json): ImpersonationRequest
    {
        if (! is_string($json)) {
            throw TokenRejected::unknown();
        }

        try {
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw TokenRejected::unknown();
        }

        if (! is_array($data)) {
            throw TokenRejected::unknown();
        }

        $narrowed = [];

        foreach ($data as $key => $value) {
            $narrowed[(string) $key] = $value;
        }

        return ImpersonationRequest::fromArray($narrowed);
    }

    private function table(): Builder
    {
        $connection = $this->settings->nullableString('tokens.connection')
            ?? $this->settings->nullableString('audit.connection');

        return $this->connections->connection($connection)
            ->table($this->settings->string('tokens.table', 'impersonator_tokens'));
    }
}
