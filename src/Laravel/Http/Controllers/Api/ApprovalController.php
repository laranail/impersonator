<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalDecision;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Laravel\Http\Requests\Api\DecideApprovalRequest;
use Simtabi\Laranail\Impersonator\Laravel\Http\Requests\Api\ListApprovalsRequest;
use Simtabi\Laranail\Impersonator\Laravel\Http\Resources\ApprovalResource;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Services\ApprovalService;

/**
 * The break-glass queue over HTTP+JSON.
 *
 * Thin, like the other API controllers: the approve permission and the requester-is-not-the-approver
 * rule live in the action, so no authorization appears here beyond establishing a caller. Refusals
 * surface as 403 (not permitted) and 409 (already decided, expired, or your own request) through the
 * renderers the service provider registers.
 *
 * There is no `store` — a break-glass request is not something a client posts. It is opened by
 * `POST /impersonations` once the authorization stack has passed, which is what stops an operator
 * queueing a request for an account they were never allowed to reach.
 */
final readonly class ApprovalController
{
    public function __construct(
        private ApprovalService $approvals,
        private ImpersonationManager $manager,
    ) {}

    /** Requests awaiting a decision — gated on the approve permission by the Form Request. */
    public function index(ListApprovalsRequest $request): JsonResponse
    {
        $queue = $this->approvals->queue($request->perPage(), $request->offset());

        return ApprovalResource::collection($queue)
            ->additional(['meta' => [
                'count' => count($queue),
                'offset' => $request->offset(),
            ]])
            ->response();
    }

    /**
     * The caller's own requests.
     *
     * No permission: an operator can always see what they themselves asked for, whatever became of
     * it. Withholding that would leave somebody unable to tell whether their request was refused or
     * simply never answered.
     */
    public function mine(): JsonResponse
    {
        $operator = $this->manager->currentImpersonatorOrNull();

        if ($operator === null) {
            return new JsonResponse(['message' => 'Unauthenticated.'], 401);
        }

        $mine = $this->approvals->mine($this->manager->identities()->fromUser($operator));

        return ApprovalResource::collection($mine)
            ->additional(['meta' => ['count' => count($mine)]])
            ->response();
    }

    public function show(string $approval): JsonResponse
    {
        $request = $this->approvals->find($approval)
            ?? abort(404, 'No approval request found for that id.');

        return $this->respond($request);
    }

    /**
     * Approve — which authorises the *requester* to enter, once, from their own session.
     *
     * Deliberately does not start the impersonation. If granting entered on the approver's behalf,
     * the audit trail would name the person who permitted the work rather than the one who did it.
     */
    public function grant(DecideApprovalRequest $request, string $approval): JsonResponse
    {
        return $this->respond(
            $this->approvals->grant($approval, null, $request->note()),
            'Approved. The requester may now enter once, until the request expires.',
        );
    }

    public function deny(DecideApprovalRequest $request, string $approval): JsonResponse
    {
        return $this->respond(
            $this->approvals->deny($approval, null, $request->note()),
            'Denied.',
        );
    }

    private function respond(ApprovalRequest $request, ?string $message = null): JsonResponse
    {
        $resource = ApprovalResource::make($request);

        // The chain goes in `meta`, not in `data`. `data` is the request's own shape and a client may
        // reasonably persist it; the chain is progress, changes under them, and is two extra queries —
        // so it belongs beside the resource rather than inside it.
        $meta = [
            'progress' => $this->approvals->progress($request),
            'decisions' => array_map(
                static fn (ApprovalDecision $decision): array => $decision->toArray(),
                $this->approvals->decisions($request->id),
            ),
        ];

        if ($message !== null) {
            $meta['message'] = $message;
        }

        $resource->additional(['meta' => $meta]);

        return $resource->response();
    }
}
