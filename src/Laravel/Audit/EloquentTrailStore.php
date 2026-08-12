<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Audit;

use Simtabi\Laranail\Impersonator\Core\Contracts\FailureReporter;
use Simtabi\Laranail\Impersonator\Core\Contracts\TrailStore;
use Simtabi\Laranail\Impersonator\Core\Enums\Criticality;
use Simtabi\Laranail\Impersonator\Core\Exceptions\OperationFailed;
use Simtabi\Laranail\Impersonator\Core\Values\TrailEvent;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAuditEvent;
use Throwable;

/**
 * The durable action trail.
 *
 * Writes sit on the hot path of every impersonated request, which drives the one
 * unusual decision here: a failed trail write is **degradable**. It reports through
 * the central handler and continues, because turning observability into a 500 makes
 * the whole feature something operators switch off — and a package that loses the
 * request it was recording is strictly better than one that loses the request
 * itself.
 *
 * That classification is about the trail only. The session-level audit row is
 * critical and is never suppressed: an impersonation with no record of it happening
 * is the outcome that must be impossible.
 */
final readonly class EloquentTrailStore implements TrailStore
{
    public function __construct(private FailureReporter $reporter) {}

    public function record(TrailEvent $event): void
    {
        try {
            $this->newModel()->forceFill($this->attributes($event))->save();
        } catch (Throwable $failure) {
            $this->reportDegraded($failure, $event, 1);
        }
    }

    public function recordMany(iterable $events): void
    {
        $rows = [];

        foreach ($events as $event) {
            $rows[] = $this->attributes($event) + ['id' => (string) $this->newModel()->newUniqueId()];
        }

        if ($rows === []) {
            return;
        }

        try {
            $this->newModel()->newQuery()->insert($rows);
        } catch (Throwable $failure) {
            $this->reportDegraded($failure, null, count($rows));
        }
    }

    public function forAudit(string $auditId, int $limit = 500, int $offset = 0): array
    {
        $events = [];

        $rows = $this->newModel()->newQuery()
            ->where('audit_id', $auditId)
            ->orderBy('occurred_at')
            ->orderBy('id')
            ->offset(max(0, $offset))
            ->limit(max(1, $limit))
            ->get();

        foreach ($rows as $row) {
            $events[] = $row->toTrailEvent();
        }

        return $events;
    }

    public function countForAudit(string $auditId): int
    {
        return $this->newModel()->newQuery()->where('audit_id', $auditId)->count();
    }

    public function purgeForAudit(string $auditId): int
    {
        $deleted = $this->newModel()->newQuery()->where('audit_id', $auditId)->delete();

        return is_int($deleted) ? $deleted : 0;
    }

    /** @return array<string, mixed> */
    private function attributes(TrailEvent $event): array
    {
        return [
            'audit_id' => $event->auditId,
            'method' => mb_substr(strtoupper($event->method), 0, 10),
            'path' => $event->path,
            'route_name' => $event->routeName,
            'status' => $event->status,
            'duration_ms' => $event->durationMs === null ? null : (int) round($event->durationMs),
            'payload' => $event->payload,
            'occurred_at' => $event->occurredAt ?? now(),
        ];
    }

    /**
     * Reports and continues. The context carries the audit id so the gap in a trail
     * is traceable to the request that failed to record, and never the payload —
     * a failing write is exactly where raw input tends to get dumped into a log.
     */
    private function reportDegraded(Throwable $failure, ?TrailEvent $event, int $lostEvents): void
    {
        $this->reporter->report(
            OperationFailed::from(
                operation: 'impersonator.trail.record',
                criticality: Criticality::Degradable,
                previous: $failure,
                expected: 'the action trail event to be persisted',
                identifiers: array_filter([
                    'audit_id' => $event?->auditId,
                    'method' => $event?->method,
                    'route_name' => $event?->routeName,
                    'lost_events' => $lostEvents,
                ], static fn (mixed $value): bool => $value !== null),
            ),
        );
    }

    private function newModel(): ImpersonationAuditEvent
    {
        return new ImpersonationAuditEvent;
    }
}
