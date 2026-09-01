<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Contracts;

use Simtabi\Laranail\Impersonator\Core\Values\TrailEvent;

/**
 * The action-level record: one row per request made while impersonating, in
 * `impersonator_audit_events`, child of an audit row.
 *
 * Writes sit on the hot path of every impersonated request, so implementations
 * must be cheap and must never fail the request they are recording — a trail
 * write that throws would turn observability into an outage. Sampling and the
 * payload decision are applied by the bridge before an event reaches here.
 */
interface TrailStore
{
    /** Append one action to an audit row's trail. */
    public function record(TrailEvent $event): void;

    /**
     * Append several at once, for buffered or queued recording.
     *
     * @param  iterable<TrailEvent>  $events
     */
    public function recordMany(iterable $events): void;

    /**
     * The trail for one audit row, oldest first. Backs the detail endpoint and
     * the export command, both of which page rather than load a long session
     * whole.
     *
     * @return list<TrailEvent>
     */
    public function forAudit(string $auditId, int $limit = 500, int $offset = 0): array;

    public function countForAudit(string $auditId): int;

    /**
     * Remove every event belonging to an audit row. Called when a parent row is
     * pruned, so a retention sweep cannot orphan its children.
     *
     * @return int the number of events removed
     */
    public function purgeForAudit(string $auditId): int;
}
