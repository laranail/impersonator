<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Audit;

use DateTimeImmutable;
use Illuminate\Support\Str;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Exceptions\AuditRowMissing;
use Simtabi\Laranail\Impersonator\Core\Values\Credential;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * An AuditStore that keeps rows in process memory.
 *
 * Intended for tests and for exercising a driver without a database. It is
 * emphatically **not** an audit trail: rows vanish when the process ends, they
 * are invisible to other workers, and remote revocation therefore cannot work
 * across requests at all. The doctor command reports it as a failure when it is
 * the active binding.
 *
 * It exists because the ordering the AuditStore contract requires — open the row,
 * then authenticate — means a driver cannot function without some implementation,
 * and a test should not need a migrated database to assert that a driver
 * regenerated a session id.
 */
final class InMemoryAuditStore implements AuditStore
{
    /** @var array<string, ImpersonationSession> */
    private array $rows = [];

    /** @var array<string, array{by: Identity|null, note: string|null}> */
    private array $revocations = [];

    public function open(
        ImpersonationRequest $request,
        ?Credential $credential = null,
        ?DateTimeImmutable $expiresAt = null,
    ): ImpersonationSession {
        $id = strtolower((string) Str::ulid());

        return $this->rows[$id] = new ImpersonationSession(
            auditId: $id,
            impersonator: $request->impersonator,
            target: $request->target,
            mode: $request->mode,
            guards: $request->guards,
            driver: $request->driver,
            adapter: $request->adapter,
            startedAt: new DateTimeImmutable,
            tenantId: $request->tenantId,
            sessionId: $credential?->reference,
            credentialHash: $credential?->hash,
            reason: $request->reason,
            expiresAt: $expiresAt,
            metadata: $request->metadata,
        );
    }

    public function close(string $auditId, EndReason $reason, ?DateTimeImmutable $at = null): ImpersonationSession
    {
        $row = $this->rows[$auditId] ?? throw AuditRowMissing::for($auditId);

        // Idempotent: a `left` arriving after a `revoked` must not erase the fact
        // that an administrator intervened.
        if ($row->hasEnded()) {
            return $row;
        }

        return $this->rows[$auditId] = $row->ended($reason, $at ?? new DateTimeImmutable);
    }

    public function attachCredential(string $auditId, Credential $credential): void
    {
        $row = $this->rows[$auditId] ?? throw AuditRowMissing::for($auditId);

        $this->rows[$auditId] = new ImpersonationSession(
            auditId: $row->auditId,
            impersonator: $row->impersonator,
            target: $row->target,
            mode: $row->mode,
            guards: $row->guards,
            driver: $row->driver,
            adapter: $row->adapter,
            startedAt: $row->startedAt,
            endedAt: $row->endedAt,
            endedBy: $row->endedBy,
            tenantId: $row->tenantId,
            sessionId: $credential->reference ?? $row->sessionId,
            credentialHash: $credential->hash ?? $row->credentialHash,
            reason: $row->reason,
            expiresAt: $row->expiresAt,
            metadata: $row->metadata,
        );
    }

    public function find(string $auditId): ?ImpersonationSession
    {
        return $this->rows[$auditId] ?? null;
    }

    public function findActiveBySessionId(string $sessionId): ?ImpersonationSession
    {
        foreach ($this->rows as $row) {
            if ($row->isActive() && $row->sessionId === $sessionId) {
                return $row;
            }
        }

        return null;
    }

    public function findActiveByCredentialHash(string $credentialHash): ?ImpersonationSession
    {
        foreach ($this->rows as $row) {
            if ($row->isActive() && $row->credentialHash !== null
                && hash_equals($row->credentialHash, $credentialHash)) {
                return $row;
            }
        }

        return null;
    }

    public function markRevoked(string $auditId, ?Identity $revokedBy = null, ?string $note = null): void
    {
        $this->revocations[$auditId] = ['by' => $revokedBy, 'note' => $note];

        $row = $this->rows[$auditId] ?? null;

        if ($row !== null && ! $row->isRevoked()) {
            $this->rows[$auditId] = $row->revoked(new DateTimeImmutable);
        }
    }

    public function isRevoked(string $auditId): bool
    {
        return isset($this->revocations[$auditId]);
    }

    public function activeFor(Identity $impersonator): array
    {
        return array_values(array_filter(
            $this->rows,
            static fn (ImpersonationSession $row): bool => $row->isActive()
                && $row->impersonator->is($impersonator),
        ));
    }

    public function activeTargeting(Identity $target): array
    {
        return array_values(array_filter(
            $this->rows,
            static fn (ImpersonationSession $row): bool => $row->isActive()
                && $row->target->is($target),
        ));
    }

    public function countActiveFor(Identity $impersonator): int
    {
        return count($this->activeFor($impersonator));
    }

    public function closeStale(DateTimeImmutable $olderThan): int
    {
        $closed = 0;

        foreach ($this->rows as $id => $row) {
            if ($row->isActive() && $row->startedAt < $olderThan) {
                $this->rows[$id] = $row->ended(EndReason::SessionLost, new DateTimeImmutable);
                $closed++;
            }
        }

        return $closed;
    }

    /**
     * Every row, for assertions. Not part of the AuditStore contract — the
     * contract has no "read everything" operation because a durable store must
     * page instead.
     *
     * @return array<string, ImpersonationSession>
     */
    public function all(): array
    {
        return $this->rows;
    }

    public function flush(): void
    {
        $this->rows = [];
        $this->revocations = [];
    }
}
