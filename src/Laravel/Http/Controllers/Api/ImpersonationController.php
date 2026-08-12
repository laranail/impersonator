<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Laravel\Http\Requests\Api\RevokeImpersonationApiRequest;
use Simtabi\Laranail\Impersonator\Laravel\Http\Requests\Api\StartImpersonationRequest;
use Simtabi\Laranail\Impersonator\Laravel\Http\Resources\ImpersonationResource;
use Simtabi\Laranail\Impersonator\Laravel\Http\Resources\StartedImpersonationResource;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Services\ImpersonationService;

/**
 * The impersonation lifecycle over HTTP+JSON.
 *
 * Thin by construction: validation is in the Form Requests, the decision in the AuthorizationPolicy,
 * the orchestration in the service, the serialisation in the resources. Refusals surface as 403/429
 * through the exception renderer registered by the service provider, so no error handling appears
 * here — an endpoint that formatted its own denial would be a second place for the message to drift.
 */
final readonly class ImpersonationController
{
    public function __construct(
        private ImpersonationService $impersonations,
        private ImpersonationManager $manager,
    ) {}

    /**
     * Start an impersonation.
     *
     * 201 rather than 200: this creates something — an audit row, and either a live session or a
     * pending handoff. The response is the one and only place a credential or accept URL appears.
     */
    public function store(StartImpersonationRequest $request): JsonResponse
    {
        $outcome = $this->impersonations->enterRequest($request->toImpersonationRequest());

        return StartedImpersonationResource::make($outcome)
            ->response()
            ->setStatusCode(201);
    }

    /**
     * The impersonation active on this request, if any.
     *
     * 204 for "not impersonating" rather than a 404: the resource is the caller's own state, which
     * exists and is simply empty. A 404 would suggest the endpoint was wrong.
     */
    public function current(): JsonResponse
    {
        $session = $this->manager->current();

        if ($session === null) {
            return new JsonResponse(status: 204);
        }

        return ImpersonationResource::make($session)->response();
    }

    /**
     * Leave the current impersonation.
     *
     * Unauthorised on purpose — leaving only de-escalates, and an operator whose access was revoked
     * mid-session must still be able to stop. 204 when there was nothing to leave, so a client
     * retrying is not punished for it.
     */
    public function destroy(): JsonResponse
    {
        $session = $this->impersonations->leave(EndReason::Left);

        if ($session === null) {
            return new JsonResponse(status: 204);
        }

        return ImpersonationResource::make($session)->response();
    }

    /**
     * End somebody else's impersonation.
     *
     * Returns the row as it now stands, which is *revoked but possibly still active*: for a session
     * credential the flag is what the target's next request sees. The response says so rather than
     * implying the session is already gone.
     */
    public function revoke(RevokeImpersonationApiRequest $request, string $audit): JsonResponse
    {
        $operator = $this->manager->currentImpersonatorOrNull();
        $note = $request->input('note');

        $session = $this->impersonations->revoke(
            auditId: $audit,
            revokedBy: $operator === null ? null : $this->manager->identities()->fromUser($operator),
            note: is_string($note) ? $note : null,
        );

        return ImpersonationResource::make($session)
            ->additional(['meta' => [
                'terminated' => $session->hasEnded(),
                'message' => $session->hasEnded()
                    ? 'The impersonation has ended.'
                    : 'Revocation recorded. The session ends on its next request.',
            ]])
            ->response();
    }
}
