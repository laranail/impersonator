<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Models;

use DateTimeImmutable;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalState;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;

/**
 * One row per break-glass approval — the four-eyes control.
 *
 * Transitions are one-way and terminal: pending becomes approved, denied or expired, and an
 * approved permit becomes consumed exactly once. There is no path back to pending, because a
 * re-openable approval is a reusable one.
 *
 * @property string $id
 * @property string $state
 */
class ImpersonationApprovalRequest extends Model
{
    use HasUlids;
    use MassPrunable;

    protected $guarded = [];

    public function getTable(): string
    {
        $table = config('laranail.impersonator.approval.table', 'impersonator_approval_requests');

        return is_string($table) && $table !== '' ? $table : 'impersonator_approval_requests';
    }

    public function getConnectionName(): ?string
    {
        // Shares the audit connection: an approval and the impersonation it authorised are read
        // together by anyone reconstructing what happened, and splitting them across connections
        // would make that join impossible.
        $connection = config('laranail.impersonator.audit.connection');

        return is_string($connection) && $connection !== '' ? $connection : parent::getConnectionName();
    }

    /** @return MorphTo<Model, $this> */
    public function requester(): MorphTo
    {
        return $this->morphTo('requester');
    }

    /** @return MorphTo<Model, $this> */
    public function impersonatable(): MorphTo
    {
        return $this->morphTo('impersonatable');
    }

    /**
     * Retention.
     *
     * Only *decided* rows are prunable, and only past their retention window. An open request
     * is never pruned however old it looks — deleting one silently would remove the record that
     * somebody asked for access to an account, which is exactly what an auditor came for.
     *
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        $days = config('laranail.impersonator.approval.retention_days');

        if (! is_numeric($days) || (int) $days <= 0) {
            return static::query()->whereRaw('1 = 0');
        }

        return static::query()
            ->whereNotIn('state', [ApprovalState::Pending->value, ApprovalState::Approved->value])
            ->where('created_at', '<=', now()->subDays((int) $days));
    }

    /**
     * @param Builder<self> $query
     *
     * @return Builder<self>
     */
    public function scopeAwaitingDecision(Builder $query): Builder
    {
        return $query->where('state', ApprovalState::Pending->value);
    }

    /** Project the row into the Core layer's read model. */
    public function toApprovalRequest(): ApprovalRequest
    {
        $stored = $this->getAttribute('request');
        $request = ImpersonationRequest::fromArray(is_array($stored) ? $this->stringKeyed($stored) : []);

        return new ApprovalRequest(
            id: $this->str('id'),
            requester: new Identity($this->str('requester_type'), $this->str('requester_id')),
            target: new Identity($this->str('impersonatable_type'), $this->str('impersonatable_id')),
            mode: Mode::of($this->str('mode', Mode::FULL)),
            request: $request,
            state: ApprovalState::tryFrom($this->str('state')) ?? ApprovalState::Pending,
            expiresAt: $this->immutable('expires_at') ?? new DateTimeImmutable,
            reason: $this->stringOrNull('reason'),
            // `decidedBy` and `decisionNote` are not columns on this table any more — each reviewer's
            // answer lives in impersonator_approval_decisions. The store fills them in as a rollup
            // when it hydrates a single request, because this model cannot see the child table without
            // an extra query per row and a queue of fifty would pay it fifty times.
            decidedAt: $this->immutable('decided_at'),
            auditId: $this->stringOrNull('audit_id'),
            createdAt: $this->immutable('created_at'),
        );
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'request'     => 'array',
            'decided_at'  => 'datetime',
            'consumed_at' => 'datetime',
            'expires_at'  => 'datetime',
        ];
    }

    private function str(string $attribute, string $default = ''): string
    {
        $value = $attribute === 'id' ? $this->getKey() : $this->getAttribute($attribute);

        return is_scalar($value) && (string) $value !== '' ? (string) $value : $default;
    }

    private function stringOrNull(string $attribute): ?string
    {
        $value = $this->getAttribute($attribute);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function immutable(string $attribute): ?DateTimeImmutable
    {
        $value = $this->getAttribute($attribute);

        return $value instanceof DateTimeInterface
            ? DateTimeImmutable::createFromInterface($value)
            : null;
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @return array<string, mixed>
     */
    private function stringKeyed(array $data): array
    {
        $narrowed = [];

        foreach ($data as $key => $value) {
            $narrowed[(string) $key] = $value;
        }

        return $narrowed;
    }
}
