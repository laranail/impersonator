<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Audit;

use DateTimeImmutable;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Builder;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Exceptions\AuditRowMissing;
use Simtabi\Laranail\Impersonator\Core\Support\AuditChain;
use Simtabi\Laranail\Impersonator\Core\Values\Credential;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * The durable audit store.
 *
 * Two things here are load-bearing beyond ordinary persistence:
 *
 *  - **The per-request lookups are cached.** `findActiveBySessionId` runs on every
 *    impersonated request to enforce revocation and `max_duration`, and a database
 *    round trip per request is the reason most packages do not offer a kill switch
 *    at all. The cache is invalidated on both `close()` and `markRevoked()`, which
 *    is what keeps the switch prompt rather than eventually-consistent.
 *  - **The concurrency cap is enforced inside a locked transaction.** A count read
 *    and an insert performed afterwards is a race that two simultaneous requests
 *    can both win, so the check and the write happen together under a row lock.
 */
class EloquentAuditStore implements AuditStore
{
    public function __construct(
        protected Settings $settings,
        protected Cache $cache,
        protected ConnectionInterface $connection,
        protected ?AuditChain $chain = null,
    ) {}

    public function open(
        ImpersonationRequest $request,
        ?Credential $credential = null,
        ?DateTimeImmutable $expiresAt = null,
    ): ImpersonationSession {
        $max = $this->settings->positiveIntOrNull('limits.max_active_per_impersonator');
        $denyWhenBusy = $this->settings->bool('limits.deny_when_target_busy', false);

        // No cap and no busy check means no reason to pay for a transaction.
        if ($max === null && ! $denyWhenBusy) {
            return $this->insert($request, $credential, $expiresAt)->toSession();
        }

        return $this->connection->transaction(function () use (
            $request,
            $credential,
            $expiresAt,
            $max,
            $denyWhenBusy,
        ): ImpersonationSession {
            if ($max !== null) {
                $active = $this->newQuery()
                    ->where('impersonator_type', $request->impersonator->type)
                    ->where('impersonator_id', (string) $request->impersonator->id)
                    ->whereNull('ended_at')
                    ->lockForUpdate()
                    ->count();

                if ($active >= $max) {
                    throw ConcurrencyLimitReached::forImpersonator($active, $max);
                }
            }

            if ($denyWhenBusy) {
                $busy = $this->newQuery()
                    ->where('target_type', $request->target->type)
                    ->where('target_id', (string) $request->target->id)
                    ->whereNull('ended_at')
                    ->where(function ($query) use ($request): void {
                        $query->where('impersonator_type', '!=', $request->impersonator->type)
                            ->orWhere('impersonator_id', '!=', (string) $request->impersonator->id);
                    })
                    ->lockForUpdate()
                    ->exists();

                if ($busy) {
                    throw ConcurrencyLimitReached::targetBusy($request->target->key());
                }
            }

            return $this->insert($request, $credential, $expiresAt)->toSession();
        });
    }

    public function close(string $auditId, EndReason $reason, ?DateTimeImmutable $at = null): ImpersonationSession
    {
        $row = $this->newQuery()->find($auditId) ?? throw AuditRowMissing::for($auditId);

        // Idempotent, and the guard matters: a `left` arriving after a `revoked`
        // would otherwise erase the fact that an administrator intervened.
        if ($row->getAttribute('ended_at') === null) {
            $row->forceFill([
                'ended_at' => $at ?? now(),
                'ended_by' => $reason->value,
            ])->save();
        }

        $this->forget($row);

        return $row->toSession();
    }

    public function attachCredential(string $auditId, Credential $credential): void
    {
        $row = $this->newQuery()->find($auditId) ?? throw AuditRowMissing::for($auditId);

        $row->forceFill(array_filter([
            'session_id' => $credential->reference,
            'credential_hash' => $credential->hash,
        ], static fn (mixed $value): bool => $value !== null))->save();

        // The cached lookup was keyed on the old session id, which the adapter has
        // just replaced by regenerating.
        $this->forget($row);
    }

    public function find(string $auditId): ?ImpersonationSession
    {
        return $this->newQuery()->find($auditId)?->toSession();
    }

    public function findActiveBySessionId(string $sessionId): ?ImpersonationSession
    {
        $ttl = $this->settings->int('limits.state_cache.ttl', 30);

        if ($ttl <= 0) {
            return $this->loadActiveBySessionId($sessionId);
        }

        // Cached as a flat snapshot, not a serialised value object: a released
        // version that changed a property would otherwise fail to unserialise every
        // entry the previous one wrote, on every request, until the TTL drained.
        //
        // `false` is cached for a miss so a session that is not impersonating does
        // not query on every request either — the overwhelmingly common case.
        $snapshot = $this->cache->remember(
            $this->cacheKey('session:' . hash('sha256', $sessionId)),
            $ttl,
            fn (): array|false => $this->loadActiveBySessionId($sessionId)?->toSnapshot() ?? false,
        );

        return is_array($snapshot) ? ImpersonationSession::fromSnapshot($snapshot) : null;
    }

    protected function loadActiveBySessionId(string $sessionId): ?ImpersonationSession
    {
        return $this->newQuery()
            ->where('session_id', $sessionId)
            ->whereNull('ended_at')
            ->latest('started_at')
            ->first()
            ?->toSession();
    }

    public function findActiveByCredentialHash(string $credentialHash): ?ImpersonationSession
    {
        $row = $this->newQuery()
            ->where('credential_hash', $credentialHash)
            ->whereNull('ended_at')
            ->latest('started_at')
            ->first();

        return $row?->toSession();
    }

    public function markRevoked(string $auditId, ?Identity $revokedBy = null, ?string $note = null): void
    {
        $row = $this->newQuery()->find($auditId) ?? throw AuditRowMissing::for($auditId);

        // Recorded, not closed. A session can only be ended from inside itself, so
        // the flag is what its next request sees.
        $row->forceFill([
            'revoked_at' => $row->getAttribute('revoked_at') ?? now(),
            'revoked_by_type' => $revokedBy?->type,
            'revoked_by_id' => $revokedBy === null ? null : (string) $revokedBy->id,
            'revocation_note' => $note,
        ])->save();

        $this->forget($row);
    }

    public function isRevoked(string $auditId): bool
    {
        return $this->newQuery()->whereKey($auditId)->whereNotNull('revoked_at')->exists();
    }

    public function activeFor(Identity $impersonator): array
    {
        return $this->sessionsFrom(
            $this->newQuery()
                ->where('impersonator_type', $impersonator->type)
                ->where('impersonator_id', (string) $impersonator->id)
                ->whereNull('ended_at'),
        );
    }

    public function activeTargeting(Identity $target): array
    {
        return $this->sessionsFrom(
            $this->newQuery()
                ->where('target_type', $target->type)
                ->where('target_id', (string) $target->id)
                ->whereNull('ended_at'),
        );
    }

    /**
     * @param Builder<ImpersonationAudit> $query
     * @return list<ImpersonationSession>
     */
    protected function sessionsFrom(Builder $query): array
    {
        $sessions = [];

        foreach ($query->get() as $row) {
            $sessions[] = $row->toSession();
        }

        return $sessions;
    }

    public function countActiveFor(Identity $impersonator): int
    {
        return $this->newQuery()
            ->where('impersonator_type', $impersonator->type)
            ->where('impersonator_id', (string) $impersonator->id)
            ->whereNull('ended_at')
            ->count();
    }

    public function closeStale(DateTimeImmutable $olderThan): int
    {
        // A row left open forever reads as an ongoing breach, so anything nobody
        // will return to is closed as session_lost rather than left dangling.
        $rows = $this->newQuery()
            ->whereNull('ended_at')
            ->where('started_at', '<=', $olderThan)
            ->get();

        foreach ($rows as $row) {
            $key = $row->getKey();

            if (is_scalar($key)) {
                $this->close((string) $key, EndReason::SessionLost);
            }
        }

        return $rows->count();
    }

    // ── Internals ───────────────────────────────────────────────────────────

    protected function insert(
        ImpersonationRequest $request,
        ?Credential $credential,
        ?DateTimeImmutable $expiresAt,
    ): ImpersonationAudit {
        $model = $this->newModel();
        $startedAt = now();

        $facts = $this->chainFacts($request, $startedAt->toDateTimeImmutable());

        $model->forceFill([
            'impersonator_type' => $request->impersonator->type,
            'impersonator_id' => (string) $request->impersonator->id,
            'target_type' => $request->target->type,
            'target_id' => (string) $request->target->id,
            'impersonator_label' => $request->impersonator->label,
            'target_label' => $request->target->label,
            'driver' => $request->driver,
            'adapter' => $request->adapter,
            'impersonator_guard' => $request->guards->impersonator,
            'target_guard' => $request->guards->target,
            'mode' => $request->mode->name,
            'tenant_id' => $request->tenantId,
            'session_id' => $credential?->reference,
            'credential_hash' => $credential?->hash,
            'ip' => $request->ip,
            'user_agent' => $request->userAgent,
            'reason' => $request->reason,
            'metadata' => $request->metadata,
            'started_at' => $startedAt,
            'expires_at' => $expiresAt,
        ] + $this->chainColumns($facts))->save();

        return $model;
    }

    /**
     * The chain columns for a new row, or nothing when tamper evidence is off.
     *
     * The predecessor is read under a row lock, so two concurrent opens cannot both chain off the
     * same row and produce a fork that verification would report as tampering.
     *
     * @param array<string, mixed> $facts
     * @return array<string, string|null>
     */
    protected function chainColumns(array $facts): array
    {
        if ($this->chain === null) {
            return [];
        }

        $previous = $this->newQuery()
            ->whereNotNull('hash')
            ->orderByDesc('started_at')
            ->orderByDesc('id')
            ->lockForUpdate()
            ->value('hash');

        $previousHash = is_string($previous) && $previous !== '' ? $previous : null;

        return [
            'previous_hash' => $previousHash,
            'hash' => $this->chain->digest($facts, $previousHash),
        ];
    }

    /**
     * The immutable opening facts a row is chained over.
     *
     * Defined once here and reused by the verify command: a fact set that drifted between writing
     * and checking would report tampering on every row, which is worse than no chain at all.
     *
     * @return array<string, mixed>
     */
    public function chainFacts(ImpersonationRequest $request, DateTimeImmutable $startedAt): array
    {
        return [
            'impersonator' => $request->impersonator->key(),
            'target' => $request->target->key(),
            'mode' => $request->mode->name,
            'driver' => $request->driver,
            'adapter' => $request->adapter,
            'guard_impersonator' => $request->guards->impersonator,
            'guard_target' => $request->guards->target,
            'tenant_id' => $request->tenantId,
            'reason' => $request->reason,
            'started_at' => $startedAt->getTimestamp(),
        ];
    }

    /**
     * The same fact set, read back off a persisted row.
     *
     * Separate from `chainFacts()` because verification starts from a database row rather than a
     * request, and the two must agree exactly — hence both living here rather than one being
     * reconstructed by the command.
     *
     * @return array<string, mixed>
     */
    public function chainFactsFromRow(ImpersonationAudit $row): array
    {
        $startedAt = $row->getAttribute('started_at');

        $str = static function (string $attribute) use ($row): string {
            $value = $row->getAttribute($attribute);

            return is_scalar($value) ? (string) $value : '';
        };

        return [
            'impersonator' => $str('impersonator_type') . ':' . $str('impersonator_id'),
            'target' => $str('target_type') . ':' . $str('target_id'),
            'mode' => $str('mode'),
            'driver' => $str('driver'),
            'adapter' => $str('adapter'),
            'guard_impersonator' => $str('impersonator_guard'),
            'guard_target' => $str('target_guard'),
            'tenant_id' => $this->nullableString($row->getAttribute('tenant_id')),
            'reason' => $this->nullableString($row->getAttribute('reason')),
            'started_at' => $startedAt instanceof \DateTimeInterface ? $startedAt->getTimestamp() : 0,
        ];
    }

    private function nullableString(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    protected function forget(ImpersonationAudit $row): void
    {
        $sessionId = $row->getAttribute('session_id');

        if (is_string($sessionId) && $sessionId !== '') {
            $this->cache->forget($this->cacheKey('session:' . hash('sha256', $sessionId)));
        }
    }

    protected function cacheKey(string $suffix): string
    {
        return $this->settings->string('limits.state_cache.prefix', 'impersonator:state:') . $suffix;
    }

    protected function newModel(): ImpersonationAudit
    {
        return new ImpersonationAudit;
    }

    /** @return Builder<ImpersonationAudit> */
    protected function newQuery(): Builder
    {
        return $this->newModel()->newQuery();
    }
}
