<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use DateTimeImmutable;
use SensitiveParameter;
use Simtabi\Laranail\Impersonator\Core\Enums\CredentialType;

/**
 * What an AuthAdapter produced so the caller can act as the target.
 *
 * For stateful guards this is `CredentialType::Session` with no secret at all —
 * the adapter mutated the session and there is nothing to hand back. For the
 * API adapters it wraps a bearer secret that is readable exactly once and is
 * never recoverable afterwards: only `hash` reaches the audit row, and
 * `reference` (a token id) is what revocation later acts on.
 */
final readonly class Credential
{
    /** @param array<string, mixed> $metadata */
    private function __construct(
        public CredentialType $type,
        #[SensitiveParameter]
        private ?string $secret = null,
        public ?string $hash = null,
        public ?string $reference = null,
        public ?DateTimeImmutable $expiresAt = null,
        public array $metadata = [],
    ) {}

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return ['secret' => $this->secret === null ? null : '[redacted]'] + $this->toAuditArray();
    }

    /** No secret leaves the server; the session itself is the credential. */
    public static function session(?string $sessionId = null): self
    {
        return new self(
            type: CredentialType::Session,
            hash: $sessionId === null ? null : hash('sha256', $sessionId),
            reference: $sessionId,
        );
    }

    /** @param array<string, mixed> $metadata */
    public static function bearer(
        CredentialType $type,
        #[SensitiveParameter]
        string $secret,
        ?string $reference = null,
        ?DateTimeImmutable $expiresAt = null,
        array $metadata = [],
    ): self {
        return new self(
            type: $type,
            secret: $secret,
            hash: hash('sha256', $secret),
            reference: $reference,
            expiresAt: $expiresAt,
            metadata: $metadata,
        );
    }

    /**
     * The one-time secret, or null for session credentials. Serialise this into
     * exactly one response and never store it.
     */
    public function secret(): ?string
    {
        return $this->secret;
    }

    public function hasSecret(): bool
    {
        return $this->secret !== null;
    }

    /**
     * The audit-safe projection: type, hash, reference and expiry, never the
     * secret. This is what both the audit row and API list responses use.
     *
     * @return array<string, mixed>
     */
    public function toAuditArray(): array
    {
        return [
            'type' => $this->type->value,
            'hash' => $this->hash,
            'reference' => $this->reference,
            'expires_at' => $this->expiresAt?->format(DATE_ATOM),
            'metadata' => $this->metadata,
        ];
    }
}
