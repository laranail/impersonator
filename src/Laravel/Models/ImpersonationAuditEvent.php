<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Models;

use DateTimeImmutable;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Simtabi\Laranail\Impersonator\Core\Values\TrailEvent;

/**
 * One action taken while impersonating — a child of an audit row.
 *
 * This is the difference between knowing an operator was in an account and knowing
 * what they did there, which is the question a compliance review actually asks.
 *
 * No timestamps: `occurred_at` is the only time that matters, and a created_at
 * duplicating it on a table that receives a row per request is pure write cost.
 */
class ImpersonationAuditEvent extends Model
{
    use HasUlids;

    public $timestamps = false;

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'payload' => 'array',
            'occurred_at' => 'datetime',
            'status' => 'integer',
            'duration_ms' => 'integer',
        ];
    }

    public function getTable(): string
    {
        $table = config('impersonator.trail.table', 'impersonator_audit_events');

        return is_string($table) && $table !== '' ? $table : 'impersonator_audit_events';
    }

    public function getConnectionName(): ?string
    {
        $connection = config('impersonator.audit.connection');

        return is_string($connection) && $connection !== '' ? $connection : parent::getConnectionName();
    }

    /** @return BelongsTo<ImpersonationAudit, $this> */
    public function audit(): BelongsTo
    {
        return $this->belongsTo(ImpersonationAudit::class, 'audit_id');
    }

    private function str(string $attribute): string
    {
        $value = $this->getAttribute($attribute);

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * @param array<array-key, mixed> $payload
     * @return array<string, mixed>
     */
    private function stringKeyed(array $payload): array
    {
        $narrowed = [];

        foreach ($payload as $key => $value) {
            $narrowed[(string) $key] = $value;
        }

        return $narrowed;
    }

    public function toTrailEvent(): TrailEvent
    {
        $occurred = $this->getAttribute('occurred_at');
        $duration = $this->getAttribute('duration_ms');

        $routeName = $this->getAttribute('route_name');
        $status = $this->getAttribute('status');
        $payload = $this->getAttribute('payload');

        return new TrailEvent(
            auditId: $this->str('audit_id'),
            method: $this->str('method'),
            path: $this->str('path'),
            routeName: is_string($routeName) && $routeName !== '' ? $routeName : null,
            status: is_int($status) ? $status : null,
            durationMs: is_int($duration) ? (float) $duration : null,
            payload: is_array($payload) ? $this->stringKeyed($payload) : null,
            occurredAt: $occurred instanceof DateTimeInterface
                ? DateTimeImmutable::createFromInterface($occurred)
                : null,
        );
    }
}
