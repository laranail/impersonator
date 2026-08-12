<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use DateTimeImmutable;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Exceptions\InvalidIdentity;

/**
 * A started impersonation, as the Core layer sees it.
 *
 * This is the read model over one `impersonator_audits` row: the audit row and
 * the live session are the same fact, which is what makes remote revocation
 * possible at all — an administrator marks the row, and the middleware on the
 * next request of that session sees it.
 *
 * `auditId` is the ULID primary key of that row and the correlation id tying
 * together the trail events, the issued credential and every log line.
 */
final readonly class ImpersonationSession
{
    /** @param array<string, mixed> $metadata */
    public function __construct(
        public string $auditId,
        public Identity $impersonator,
        public Identity $target,
        public Mode $mode,
        public Guards $guards,
        public string $driver,
        public string $adapter,
        public DateTimeImmutable $startedAt,
        public ?DateTimeImmutable $endedAt = null,
        public ?EndReason $endedBy = null,
        public ?string $tenantId = null,
        public ?string $sessionId = null,
        public ?string $credentialHash = null,
        public ?string $reason = null,
        public ?DateTimeImmutable $expiresAt = null,
        public array $metadata = [],
        public ?DateTimeImmutable $revokedAt = null,
    ) {}

    public function isActive(): bool
    {
        return $this->endedAt === null;
    }

    /**
     * Whether an administrator has marked this for termination.
     *
     * Distinct from `hasEnded()`, and the distinction is the kill switch: a session
     * can only be ended from inside itself, so revocation is recorded first and the
     * session's next request is what closes it. Between those two moments the row is
     * both active and revoked.
     */
    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }

    /** Whether this must be terminated on sight — revoked, or past its expiry. */
    public function mustTerminate(DateTimeImmutable $now): bool
    {
        return $this->isRevoked() || $this->isExpiredAt($now);
    }

    public function hasEnded(): bool
    {
        return $this->endedAt !== null;
    }

    /**
     * Whether `max_duration` has elapsed. Returns false when no expiry was set,
     * since an unlimited duration is a valid (if inadvisable) configuration.
     */
    public function isExpiredAt(DateTimeImmutable $now): bool
    {
        return $this->expiresAt !== null && $now > $this->expiresAt;
    }

    /** Seconds elapsed, measured to the end for closed sessions. */
    public function durationInSeconds(DateTimeImmutable $now): int
    {
        return ($this->endedAt ?? $now)->getTimestamp() - $this->startedAt->getTimestamp();
    }

    /**
     * Mark this as revoked without ending it.
     *
     * The row stays active on purpose: a session can only be terminated from inside
     * itself, so revocation records the intent and the session's next request is
     * what closes it.
     */
    public function revoked(DateTimeImmutable $at): self
    {
        return new self(
            $this->auditId,
            $this->impersonator,
            $this->target,
            $this->mode,
            $this->guards,
            $this->driver,
            $this->adapter,
            $this->startedAt,
            $this->endedAt,
            $this->endedBy,
            $this->tenantId,
            $this->sessionId,
            $this->credentialHash,
            $this->reason,
            $this->expiresAt,
            $this->metadata,
            $this->revokedAt ?? $at,
        );
    }

    public function ended(EndReason $reason, DateTimeImmutable $at): self
    {
        return new self(
            $this->auditId,
            $this->impersonator,
            $this->target,
            $this->mode,
            $this->guards,
            $this->driver,
            $this->adapter,
            $this->startedAt,
            $at,
            $reason,
            $this->tenantId,
            $this->sessionId,
            $this->credentialHash,
            $this->reason,
            $this->expiresAt,
            $this->metadata,
            $this->revokedAt,
        );
    }

    /**
     * The complete state, for a cache entry the enforcement middleware reads on
     * every request.
     *
     * Separate from `toArray()` because the two have opposite requirements: that one
     * is a deliberately reduced projection for anything a client can see, while this
     * one must be lossless or the middleware would decide on partial state.
     *
     * Flat scalars only, so a cached entry stays readable across a release that
     * changes this class — a serialised object would fail to unserialise on every
     * request until the TTL drained.
     *
     * @return array<string, mixed>
     */
    public function toSnapshot(): array
    {
        return [
            'v' => 1,
            'id' => $this->auditId,
            'impersonator' => $this->impersonator->toArray(),
            'target' => $this->target->toArray(),
            'mode' => $this->mode->name,
            'guard_impersonator' => $this->guards->impersonator,
            'guard_target' => $this->guards->target,
            'driver' => $this->driver,
            'adapter' => $this->adapter,
            'tenant_id' => $this->tenantId,
            'session_id' => $this->sessionId,
            'credential_hash' => $this->credentialHash,
            'reason' => $this->reason,
            'started_at' => $this->startedAt->getTimestamp(),
            'ended_at' => $this->endedAt?->getTimestamp(),
            'ended_by' => $this->endedBy?->value,
            'expires_at' => $this->expiresAt?->getTimestamp(),
            'revoked_at' => $this->revokedAt?->getTimestamp(),
            'metadata' => $this->metadata,
        ];
    }

    /**
     * @param array<string, mixed> $snapshot
     *
     * @throws InvalidIdentity when the
     *                         cached identities are unreadable, which means the entry cannot be trusted
     */
    public static function fromSnapshot(array $snapshot): self
    {
        $str = static fn (string $key, string $default = ''): string => is_string($snapshot[$key] ?? null)
            && $snapshot[$key] !== ''
                ? $snapshot[$key]
                : $default;

        $at = static fn (string $key): ?DateTimeImmutable => is_int($snapshot[$key] ?? null)
            ? (new DateTimeImmutable)->setTimestamp($snapshot[$key])
            : null;

        $identity = static function (string $key) use ($snapshot): Identity {
            $data = $snapshot[$key] ?? null;

            if (! is_array($data) || ! isset($data['type'], $data['id'])) {
                throw InvalidIdentity::emptyType();
            }

            $type = $data['type'];
            $id = $data['id'];

            if (! is_string($type) || (! is_int($id) && ! is_string($id))) {
                throw InvalidIdentity::emptyType();
            }

            return new Identity($type, $id, is_string($data['label'] ?? null) ? $data['label'] : null);
        };

        $endedBy = $str('ended_by');
        $metadata = $snapshot['metadata'] ?? null;

        return new self(
            auditId: $str('id'),
            impersonator: $identity('impersonator'),
            target: $identity('target'),
            mode: Mode::of($str('mode', Mode::FULL)),
            guards: new Guards($str('guard_impersonator', 'web'), $str('guard_target', 'web')),
            driver: $str('driver', 'session'),
            adapter: $str('adapter', 'session'),
            startedAt: $at('started_at') ?? new DateTimeImmutable,
            endedAt: $at('ended_at'),
            endedBy: $endedBy === '' ? null : EndReason::tryFrom($endedBy),
            tenantId: $str('tenant_id') ?: null,
            sessionId: $str('session_id') ?: null,
            credentialHash: $str('credential_hash') ?: null,
            reason: $str('reason') ?: null,
            expiresAt: $at('expires_at'),
            metadata: is_array($metadata) ? self::stringKeys($metadata) : [],
            revokedAt: $at('revoked_at'),
        );
    }

    /**
     * @param array<array-key, mixed> $data
     * @return array<string, mixed>
     */
    private static function stringKeys(array $data): array
    {
        $narrowed = [];

        foreach ($data as $key => $value) {
            $narrowed[(string) $key] = $value;
        }

        return $narrowed;
    }

    /**
     * The safe projection for API responses and logs. `credentialHash` and
     * `sessionId` are omitted by design — a hash is still a verifier that lets
     * a holder confirm a guessed token, and neither belongs in a list endpoint.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->auditId,
            'impersonator' => $this->impersonator->toArray(),
            'target' => $this->target->toArray(),
            'mode' => $this->mode->name,
            'guards' => $this->guards->toArray(),
            'driver' => $this->driver,
            'adapter' => $this->adapter,
            'tenant_id' => $this->tenantId,
            'reason' => $this->reason,
            'started_at' => $this->startedAt->format(DATE_ATOM),
            'ended_at' => $this->endedAt?->format(DATE_ATOM),
            'ended_by' => $this->endedBy?->value,
            'expires_at' => $this->expiresAt?->format(DATE_ATOM),
            'revoked_at' => $this->revokedAt?->format(DATE_ATOM),
            'active' => $this->isActive(),
            'metadata' => $this->metadata,
        ];
    }
}
