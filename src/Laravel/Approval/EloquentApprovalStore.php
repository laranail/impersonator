<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Approval;

use DateTimeImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Str;
use Psr\Clock\ClockInterface;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalState;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationApprovalRequest;

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
    ) {}

    public function open(ImpersonationRequest $request, DateTimeImmutable $expiresAt): ApprovalRequest
    {
        $now = $this->clock->now();
        $id = strtolower((string) Str::ulid());

        $this->table()->insert([
            'id' => $id,
            'requester_type' => $request->impersonator->type,
            'requester_id' => (string) $request->impersonator->id,
            'target_type' => $request->target->type,
            'target_id' => (string) $request->target->id,
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

        return $this->find($id) ?? throw new \RuntimeException(
            'The approval request could not be read back after being opened.',
        );
    }

    public function find(string $id): ?ApprovalRequest
    {
        return $this->model()->newQuery()->find($id)?->toApprovalRequest();
    }

    public function grant(string $id, Identity $approver, ?string $note = null): ?ApprovalRequest
    {
        return $this->decide($id, $approver, $note, ApprovalState::Approved);
    }

    public function deny(string $id, Identity $approver, ?string $note = null): ?ApprovalRequest
    {
        return $this->decide($id, $approver, $note, ApprovalState::Denied);
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

    /**
     * @param array<array-key, ImpersonationApprovalRequest> $rows
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
     * Move a pending request to a terminal state.
     *
     * The approver is recorded in the same statement that makes the decision, so there is no
     * window in which a row is decided but nobody owns the decision.
     */
    private function decide(
        string $id,
        Identity $approver,
        ?string $note,
        ApprovalState $state,
    ): ?ApprovalRequest {
        $now = $this->clock->now();

        $decided = $this->table()
            ->where('id', $id)
            ->where('state', ApprovalState::Pending->value)
            ->where('expires_at', '>', $now)
            ->update([
                'state' => $state->value,
                'decided_by_type' => $approver->type,
                'decided_by_id' => (string) $approver->id,
                'decision_note' => $note,
                'decided_at' => $now,
                'updated_at' => $now,
            ]);

        return $decided === 1 ? $this->find($id) : null;
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
