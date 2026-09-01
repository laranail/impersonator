<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Approval;

use DateTimeImmutable;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Str;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalState;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalVerdict;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalDecision;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalPolicy;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationApprovalRequest;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * Break-glass approvals, in the database.
 *
 * Every state transition is a single conditional `UPDATE` whose affected-row count decides
 * the outcome — the same discipline as handoff-token redemption, and for the same reason. A
 * read-then-write would let two approvers both pass the "still pending?" check, and let two
 * requests both spend one permit; under load that is not a rare edge but the normal case,
 * because approval traffic arrives in bursts when an incident starts.
 *
 * The query builder rather than Eloquent for the transitions, so that `update()` returns the
 * affected-row count and no model event, cast or global scope sits in the middle of a claim.
 * Reads go through the model, because there the projection is the point.
 */
final readonly class EloquentApprovalStore implements ApprovalStore
{
    public function __construct(
        private ClockInterface $clock,
        private Settings $settings,
        private ConnectionInterface $connection,
    ) {}

    public function open(ImpersonationRequest $request, DateTimeImmutable $expiresAt): ApprovalRequest
    {
        $now = $this->clock->now();
        $id = strtolower((string) Str::ulid());

        $this->table()->insert([
            'id' => $id,
            'requester_type' => $request->impersonator->type,
            'requester_id' => (string) $request->impersonator->id,
            'impersonatable_type' => $request->target->type,
            'impersonatable_id' => (string) $request->target->id,
            'mode' => $request->mode->name,
            'reason' => $request->reason,
            'request' => json_encode($request->toArray(), JSON_THROW_ON_ERROR),
            'fingerprint' => ApprovalRequest::fingerprintFor(
                $request->impersonator,
                $request->target,
                $request->mode->name,
            ),
            'state' => ApprovalState::Pending->value,
            'expires_at' => $expiresAt,
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        return $this->find($id) ?? throw new RuntimeException(
            'The approval request could not be read back after being opened.',
        );
    }

    public function find(string $id): ?ApprovalRequest
    {
        $request = $this->model()->newQuery()->find($id)?->toApprovalRequest();

        return $request === null ? null : $this->withRollup($request);
    }

    public function grant(string $id, Identity $approver, ?string $note = null, ?string $role = null): ?ApprovalRequest
    {
        return $this->decide($id, $approver, $note, ApprovalVerdict::Approved, $role);
    }

    public function deny(string $id, Identity $approver, ?string $note = null, ?string $role = null): ?ApprovalRequest
    {
        return $this->decide($id, $approver, $note, ApprovalVerdict::Denied, $role);
    }

    /** @return list<ApprovalDecision> */
    public function decisions(string $id): array
    {
        $rows = $this->decisionsTable()
            ->where('approval_id', $id)
            ->orderBy('decided_at')
            ->orderBy('id')
            ->get();

        $decisions = [];

        foreach ($rows as $row) {
            $decisions[] = $this->toDecision($row);
        }

        return $decisions;
    }

    public function policyFor(ApprovalRequest $request): ApprovalPolicy
    {
        $policies = $this->settings->array('approval.policies');
        $mode = $request->mode->name;

        // Per mode, falling back to `default`. A `full`-access request warranting two reviewers while
        // a `read_only` one needs a single sign-off is the ordinary shape of this control.
        $config = $policies[$mode] ?? $policies['default'] ?? [];

        return ApprovalPolicy::fromArray(is_array($config) ? Settings::stringKeyed($config) : []);
    }

    public function consume(string $fingerprint, Identity $requester): ?ApprovalRequest
    {
        $now = $this->clock->now();

        // Read first only to learn *which* row to claim; the claim below is what authorises.
        // Nothing is decided on the strength of this read.
        $candidate = $this->usableQuery($fingerprint, $requester, $now)->first();

        if ($candidate === null || ! is_scalar($candidate->id)) {
            return null;
        }

        $id = (string) $candidate->id;

        // The claim. `state = approved` in the WHERE is the whole guarantee: exactly one
        // caller can move a permit out of `approved`, so a permit is spent once even if two
        // requests present it in the same millisecond.
        $claimed = $this->table()
            ->where('id', $id)
            ->where('state', ApprovalState::Approved->value)
            ->where('expires_at', '>', $now)
            ->update([
                'state' => ApprovalState::Consumed->value,
                'consumed_at' => $now,
                'updated_at' => $now,
            ]);

        if ($claimed !== 1) {
            return null;
        }

        return $this->find($id);
    }

    public function findUsable(string $fingerprint, Identity $requester): ?ApprovalRequest
    {
        $row = $this->usableQuery($fingerprint, $requester, $this->clock->now())->first();

        return $row !== null && is_scalar($row->id) ? $this->find((string) $row->id) : null;
    }

    public function pending(int $limit = 50, int $offset = 0): array
    {
        // Unexpired only. An approver queue that lists dead requests invites somebody to
        // approve one and wonder why nothing happened.
        return $this->project(
            $this->model()->newQuery()
                ->where('state', ApprovalState::Pending->value)
                ->where('expires_at', '>', $this->clock->now())
                ->orderByDesc('created_at')
                ->orderByDesc('id')
                ->limit(max(1, $limit))
                ->offset(max(0, $offset))
                ->get()
                ->all(),
        );
    }

    public function forRequester(Identity $requester, int $limit = 50, int $offset = 0): array
    {
        return $this->project(
            $this->model()->newQuery()
                ->where('requester_type', $requester->type)
                ->where('requester_id', (string) $requester->id)
                ->orderByDesc('created_at')
                ->orderByDesc('id')
                ->limit(max(1, $limit))
                ->offset(max(0, $offset))
                ->get()
                ->all(),
        );
    }

    public function attachAudit(string $id, string $auditId): void
    {
        $this->table()
            ->where('id', $id)
            ->update(['audit_id' => $auditId, 'updated_at' => $this->clock->now()]);
    }

    public function expireStale(int $limit = 500): array
    {
        $now = $this->clock->now();

        // Ids are collected before the update so the caller can announce each expiry. Sweeping
        // by a bare `UPDATE ... WHERE expires_at <= now` would be one statement, but it would
        // also mean nobody is ever told their request went unanswered — which is the single
        // most useful thing to say about a break-glass request that timed out.
        $ids = $this->table()
            ->where('state', ApprovalState::Pending->value)
            ->where('expires_at', '<=', $now)
            ->limit(max(1, $limit))
            ->pluck('id')
            ->map(static fn (mixed $id): string => is_scalar($id) ? (string) $id : '')
            ->filter(static fn (string $id): bool => $id !== '')
            ->all();

        if ($ids === []) {
            return [];
        }

        $this->table()
            ->whereIn('id', $ids)
            ->where('state', ApprovalState::Pending->value)
            ->update([
                'state' => ApprovalState::Expired->value,
                'decided_at' => $now,
                'updated_at' => $now,
            ]);

        $expired = [];

        foreach ($ids as $id) {
            $request = $this->find($id);

            if ($request !== null) {
                $expired[] = $request;
            }
        }

        return $expired;
    }

    /**
     * Fill the `decidedBy` / `decisionNote` rollup from the chain.
     *
     * One extra query, and only for a single request — never for a queue, where fifty rows would pay
     * it fifty times. The fields exist because they are published API shape; the record is the
     * decisions table.
     *
     * The closing decision is the denial if there is one, otherwise the last approval. On a partially
     * approved request it stays null: naming one reviewer there would read as "decided by them" while
     * the request is still waiting on somebody else.
     */
    private function withRollup(ApprovalRequest $request): ApprovalRequest
    {
        if (! $request->state->isDecided()) {
            return $request;
        }

        $decisions = $this->decisions($request->id);

        if ($decisions === []) {
            return $request;
        }

        $closing = null;

        foreach ($decisions as $decision) {
            if ($decision->denied()) {
                $closing = $decision;

                break;
            }

            $closing = $decision;
        }

        return $request->withDecider($closing->reviewer, $closing->note);
    }

    /**
     * @param  array<array-key, ImpersonationApprovalRequest>  $rows
     * @return list<ApprovalRequest>
     */
    private function project(array $rows): array
    {
        $requests = [];

        foreach ($rows as $row) {
            $requests[] = $row->toApprovalRequest();
        }

        return $requests;
    }

    /**
     * Record one reviewer's decision and roll the chain's state forward, atomically.
     *
     * The quorum recount is the race a chain introduces. Two reviewers granting simultaneously must
     * not both observe "one of two" and leave the request short, nor both flip it to `Approved`. So
     * the whole thing runs in one transaction holding a write lock on the **parent** row: the lock
     * serialises the recount, and the child table's unique index arbitrates duplicate reviewers.
     *
     * Order matters. The lock is taken first, then the decision is inserted, then every decision is
     * re-read and the state recomputed from all of them. Recomputing from a count captured before the
     * insert would be the same read-then-write it is here to avoid.
     */
    private function decide(
        string $id,
        Identity $approver,
        ?string $note,
        ApprovalVerdict $verdict,
        ?string $role,
    ): ?ApprovalRequest {
        $now = $this->clock->now();

        return $this->connection->transaction(function () use ($id, $approver, $note, $verdict, $role, $now): ?ApprovalRequest {
            $locked = $this->lockedRequest($id);

            if ($locked === null) {
                return null;
            }

            // Closed, or timed out. Expiry is checked here rather than trusted from the column,
            // because the column is only as fresh as the last write.
            if (! $locked->state->acceptsDecisions() || $locked->hasExpired($now)) {
                return null;
            }

            try {
                $this->decisionsTable()->insert([
                    'id' => strtolower((string) Str::ulid()),
                    'approval_id' => $id,
                    'reviewer_type' => $approver->type,
                    'reviewer_id' => (string) $approver->id,
                    'reviewer_role' => $role,
                    'verdict' => $verdict->value,
                    'note' => $note,
                    'decided_at' => $now,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
            } catch (UniqueConstraintViolationException) {
                // This reviewer has already decided. Treated as the answer rather than as an error:
                // the index is the mechanism that stops one person counting twice toward quorum, so
                // its violation is exactly the "already decided" signal the caller asked about.
                return null;
            }

            $decisions = $this->decisions($id);
            $state = $this->policyFor($locked)->stateFor($decisions);

            $this->table()->where('id', $id)->update([
                'state' => $state->value,
                // The rollup timestamp only moves once the chain closes. A partially approved request
                // has not been decided, and stamping it would make a queue sorted on `decided_at`
                // show it among the answered ones.
                'decided_at' => $state->isDecided() ? $now : null,
                'updated_at' => $now,
            ]);

            return $this->find($id);
        });
    }

    /**
     * The parent row, held under a write lock for the rest of the transaction.
     *
     * `first()` rather than an aggregate: PostgreSQL refuses `FOR UPDATE` alongside aggregate
     * functions, so a `count()` here would throw on every call. SQLite compiles the lock to nothing,
     * which is why the concurrency test for this path lives in the `locking` group.
     */
    private function lockedRequest(string $id): ?ApprovalRequest
    {
        $row = $this->model()->newQuery()->whereKey($id)->lockForUpdate()->first();

        return $row?->toApprovalRequest();
    }

    /** @param object $row a decisions-table row */
    private function toDecision(object $row): ApprovalDecision
    {
        $str = static fn (mixed $value): string => is_scalar($value) ? (string) $value : '';
        $nullable = static fn (mixed $value): ?string => is_string($value) && $value !== '' ? $value : null;

        $decidedAt = $row->decided_at ?? null;

        return new ApprovalDecision(
            reviewer: new Identity($str($row->reviewer_type ?? ''), $str($row->reviewer_id ?? '')),
            // An unreadable verdict falls to `Denied`, which is fail-closed: `Denied` is terminal, so
            // a corrupt row stops the chain instead of counting toward quorum. Defaulting to
            // `Approved` would let a garbled value authorise access to somebody's account.
            verdict: ApprovalVerdict::tryFrom($str($row->verdict ?? '')) ?? ApprovalVerdict::Denied,
            // An unreadable timestamp becomes "now" rather than throwing: this is a read model for a
            // queue, and a row that cannot be displayed is worse than one displayed with a poor date.
            decidedAt: is_string($decidedAt) ? new DateTimeImmutable($decidedAt) : $this->clock->now(),
            role: $nullable($row->reviewer_role ?? null),
            note: $nullable($row->note ?? null),
            id: $nullable($row->id ?? null),
        );
    }

    private function decisionsTable(): Builder
    {
        return $this->connection->table(
            $this->settings->string('approval.decisions_table', 'impersonator_approval_decisions'),
        );
    }

    private function usableQuery(string $fingerprint, Identity $requester, DateTimeImmutable $now): Builder
    {
        // The requester is part of the query, not checked afterwards: a permit belongs to the
        // operator who asked for it, and one colleague spending another's approval would defeat
        // the record of who was authorised to do what.
        return $this->table()
            ->where('fingerprint', $fingerprint)
            ->where('state', ApprovalState::Approved->value)
            ->where('requester_type', $requester->type)
            ->where('requester_id', (string) $requester->id)
            ->where('expires_at', '>', $now)
            ->orderByDesc('created_at');
    }

    private function model(): ImpersonationApprovalRequest
    {
        return new ImpersonationApprovalRequest;
    }

    private function table(): Builder
    {
        $model = $this->model();

        return $model->getConnection()->table($model->getTable());
    }
}
