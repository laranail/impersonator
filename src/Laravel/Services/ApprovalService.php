<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use RuntimeException;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalDenied;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ApprovalNotDecidable;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalDecision;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Laravel\Actions\DecideApproval;
use Simtabi\Laranail\Impersonator\Laravel\Actions\EnterImpersonation;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/**
 * The break-glass orchestration layer.
 *
 * The write path composes {@see DecideApproval}; the read path serves the approver queue and
 * an operator's own request history. Both live here rather than on the store so a UI, the API
 * and a console command share one set of rules about who may see what.
 *
 * Note there is no `request()` method. Opening a request is not something a caller does directly —
 * it happens inside {@see EnterImpersonation} once the authorization stack has passed, so an
 * operator cannot queue a request for an account they were never allowed to reach.
 */
final readonly class ApprovalService
{
    public function __construct(
        private ApprovalStore $approvals,
        private DecideApproval $decide,
        private ImpersonationManager $manager,
        private Dispatcher $events,
    ) {}

    /** @throws ImpersonationDenied|ApprovalNotDecidable */
    public function grant(
        string $approvalId,
        Authenticatable|Model|Identity|null $approver = null,
        ?string $note = null,
    ): ApprovalRequest {
        return $this->decide->grant($approvalId, $this->identify($approver), $note);
    }

    /** @throws ImpersonationDenied|ApprovalNotDecidable */
    public function deny(
        string $approvalId,
        Authenticatable|Model|Identity|null $approver = null,
        ?string $note = null,
    ): ApprovalRequest {
        return $this->decide->deny($approvalId, $this->identify($approver), $note);
    }

    /**
     * Every decision recorded against a request, oldest first.
     *
     * The audit answer to "who signed off". A chain whose intermediate approvals are invisible cannot
     * answer that during a review, which is the whole reason the decisions live in their own table.
     *
     * @return list<ApprovalDecision>
     */
    public function decisions(string $approvalId): array
    {
        return $this->approvals->decisions($approvalId);
    }

    /**
     * How far along a request is: what it needs, what it has, and what is still outstanding.
     *
     * For a queue that has to say more than a number. "Two of three, still needs an auditor" is the
     * sentence a reviewer can act on; "pending" is not.
     *
     * @return array{required: int, approved: int, outstanding: int, outstanding_roles: array<string, int>, policy: array<string, mixed>}
     */
    public function progress(ApprovalRequest $request): array
    {
        $policy = $this->approvals->policyFor($request);

        $approvals = array_values(array_filter(
            $this->approvals->decisions($request->id),
            static fn (ApprovalDecision $decision): bool => $decision->approved(),
        ));

        return [
            'required' => $policy->required(),
            'approved' => count($approvals),
            'outstanding' => $policy->outstandingCount($approvals),
            'outstanding_roles' => $policy->outstandingRoles($approvals),
            'policy' => $policy->toArray(),
        ];
    }

    public function find(string $approvalId): ?ApprovalRequest
    {
        return $this->approvals->find($approvalId);
    }

    /**
     * The approver's queue: unexpired, undecided requests.
     *
     * @return list<ApprovalRequest>
     */
    public function queue(int $limit = 50, int $offset = 0): array
    {
        return $this->approvals->pending($limit, $offset);
    }

    /**
     * One operator's own requests, whatever their state.
     *
     * @return list<ApprovalRequest>
     */
    public function mine(
        Authenticatable|Model|Identity|null $operator = null,
        int $limit = 50,
        int $offset = 0,
    ): array {
        return $this->approvals->forRequester($this->identify($operator), $limit, $offset);
    }

    /**
     * Whether this operator already holds a spendable permit for this target and mode.
     *
     * For screens that want to show "approved — you may now enter". Never gate an entry on
     * this: checking here and entering later is precisely the race the atomic spend inside
     * `EnterImpersonation` exists to close.
     */
    public function hasPermit(
        Authenticatable|Model|Identity $target,
        string $mode,
        Authenticatable|Model|Identity|null $operator = null,
    ): bool {
        $requester = $this->identify($operator);

        return $this->approvals->findUsable(
            ApprovalRequest::fingerprintFor($requester, $this->identify($target), $mode),
            $requester,
        ) !== null;
    }

    /**
     * Expire requests nobody answered, announcing each one.
     *
     * Housekeeping for the queue rather than a security boundary — expiry is enforced when a
     * permit is read, so a stale request is already dead whether or not this has run. What
     * this adds is the event, which is how the requester learns nobody replied.
     *
     * @return list<ApprovalRequest>
     */
    public function expireStale(int $limit = 500): array
    {
        $expired = $this->approvals->expireStale($limit);

        foreach ($expired as $request) {
            $this->events->dispatch(new ApprovalDenied($request->id, expired: true));
        }

        return $expired;
    }

    /**
     * Resolve an actor to an Identity, defaulting to the authenticated operator.
     *
     * Goes through `resolveActor` rather than the target allowlist: the allowlist governs who
     * may be *impersonated*, and an approver is on the operator side of that line.
     */
    private function identify(Authenticatable|Model|Identity|null $actor): Identity
    {
        if ($actor instanceof Identity) {
            return $actor;
        }

        if ($actor !== null) {
            return $this->manager->identities()->fromUser($actor);
        }

        $operator = $this->manager->currentImpersonatorOrNull()
            ?? throw new RuntimeException('No authenticated operator to attribute this approval decision to.');

        return $this->manager->identities()->fromUser($operator);
    }
}
