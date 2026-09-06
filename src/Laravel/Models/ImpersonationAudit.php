<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Models;

use DateTimeImmutable;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Core\Values\Guards;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * One row per impersonation — the session-level audit record.
 *
 * Append-only as far as the package is concerned: the only writes after creation are
 * the terminal transitions (ending, revoking) and the credential details that can
 * only be known once the adapter has run. There is no update or delete path exposed.
 *
 * @property string $id
 * @property string $mode
 * @property string|null $ended_by
 */
class ImpersonationAudit extends Model
{
    /** @use HasFactory<Factory<self>> */
    use HasFactory;

    use HasUlids;
    use MassPrunable;

    protected $guarded = [];

    public function getTable(): string
    {
        $table = config('laranail.impersonator.audit.table', 'impersonator_audits');

        return is_string($table) && $table !== '' ? $table : 'impersonator_audits';
    }

    public function getConnectionName(): ?string
    {
        $connection = config('laranail.impersonator.audit.connection');

        return is_string($connection) && $connection !== '' ? $connection : parent::getConnectionName();
    }

    /** @return HasMany<ImpersonationAuditEvent, $this> */
    public function events(): HasMany
    {
        return $this->hasMany(ImpersonationAuditEvent::class, 'audit_id');
    }

    /** @return MorphTo<Model, $this> */
    public function impersonator(): MorphTo
    {
        return $this->morphTo('impersonator');
    }

    /**
     * The impersonated account.
     *
     * Named for the columns (`impersonatable_type` / `impersonatable_id`) rather than for the
     * role — `target` is what it is *called* in one request, `impersonatable` is what makes it
     * eligible at all. The Core value object keeps `target`, because a framework-free session
     * has no notion of a morph column.
     *
     * @return MorphTo<Model, $this>
     */
    public function impersonatable(): MorphTo
    {
        return $this->morphTo('impersonatable');
    }

    /** @return MorphTo<Model, $this> */
    public function revokedBy(): MorphTo
    {
        return $this->morphTo('revokedBy', 'revoked_by_type', 'revoked_by_id');
    }

    /**
     * Retention, via MassPrunable so a long history does not load into memory.
     *
     * A null `retention_days` returns a query matching nothing rather than
     * everything — getting that backwards deletes the entire audit trail, which is
     * the single most destructive mistake this class could make.
     */
    /** @return Builder<static> */
    public function prunable(): Builder
    {
        $days = config('laranail.impersonator.audit.retention_days');

        if (! is_numeric($days) || (int) $days <= 0) {
            return static::query()->whereRaw('1 = 0');
        }

        return static::query()->where('started_at', '<=', now()->subDays((int) $days));
    }

    /**
     * @param Builder<self> $query
     *
     * @return Builder<self>
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->whereNull('ended_at');
    }

    /** Project the row into the Core layer's read model. */
    public function toSession(): ImpersonationSession
    {
        return new ImpersonationSession(
            auditId: $this->str('id'),
            impersonator: new Identity(
                $this->str('impersonator_type'),
                $this->str('impersonator_id'),
                $this->stringOrNull('impersonator_label'),
            ),
            target: new Identity(
                $this->str('impersonatable_type'),
                $this->str('impersonatable_id'),
                $this->stringOrNull('target_label'),
            ),
            mode: Mode::of($this->str('mode', Mode::FULL)),
            guards: new Guards(
                $this->str('impersonator_guard', 'web'),
                $this->str('target_guard', 'web'),
            ),
            driver: $this->str('driver', 'session'),
            adapter: $this->str('adapter', 'session'),
            startedAt: $this->immutable('started_at') ?? new DateTimeImmutable,
            endedAt: $this->immutable('ended_at'),
            endedBy: $this->stringOrNull('ended_by') === null
                ? null
                : EndReason::tryFrom($this->str('ended_by')),
            tenantId: $this->stringOrNull('tenant_id'),
            sessionId: $this->stringOrNull('session_id'),
            credentialHash: $this->stringOrNull('credential_hash'),
            reason: $this->stringOrNull('reason'),
            expiresAt: $this->immutable('expires_at'),
            metadata: $this->metadataArray(),
            revokedAt: $this->immutable('revoked_at'),
            extensions: $this->extensionCount(),
        );
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'metadata'    => 'array',
            'started_at'  => 'datetime',
            'expires_at'  => 'datetime',
            'ended_at'    => 'datetime',
            'revoked_at'  => 'datetime',
            'decided_at'  => 'datetime',
            'extended_at' => 'datetime',
            'extensions'  => 'integer',
        ];
    }

    /**
     * How many times this impersonation has been extended.
     *
     * Defaults to zero for a row written before the column existed, rather than being read
     * as null and breaking the policy's comparison — a published schema gains columns, and
     * the audit table is the one place old rows are guaranteed to still be around.
     */
    private function extensionCount(): int
    {
        $value = $this->getAttribute('extensions');

        return is_numeric($value) ? max(0, (int) $value) : 0;
    }

    /**
     * A required string attribute.
     *
     * The audit columns are strings so one table can hold both int-keyed and UUID-keyed
     * models — which is also why Identity compares ids loosely on their PHP type.
     */
    private function str(string $attribute, string $default = ''): string
    {
        $value = $attribute === 'id' ? $this->getKey() : $this->getAttribute($attribute);

        return is_scalar($value) && (string) $value !== '' ? (string) $value : $default;
    }

    /** @return array<string, mixed> */
    private function metadataArray(): array
    {
        $metadata = $this->getAttribute('metadata');

        if (! is_array($metadata)) {
            return [];
        }

        $narrowed = [];

        foreach ($metadata as $key => $value) {
            $narrowed[(string) $key] = $value;
        }

        return $narrowed;
    }

    private function immutable(string $attribute): ?DateTimeImmutable
    {
        $value = $this->getAttribute($attribute);

        return $value instanceof DateTimeInterface
            ? DateTimeImmutable::createFromInterface($value)
            : null;
    }

    private function stringOrNull(string $attribute): ?string
    {
        $value = $this->getAttribute($attribute);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
