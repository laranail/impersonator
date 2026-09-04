<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Services\ImpersonationService;
use Simtabi\Laranail\Impersonator\Laravel\Http\Requests\RevokeImpersonationRequest;

/**
 * Ends somebody else's impersonation.
 *
 * Records the revocation and returns immediately. The target's session is terminated by
 * the lifetime middleware on its next request, because a session can only be ended from
 * inside itself — so a successful response here means "revocation recorded", not
 * "session already destroyed", and the flash message says so.
 */
final readonly class RevokeImpersonationController
{
    public function __construct(
        private ImpersonationService $impersonations,
        private ImpersonationManager $manager,
    ) {}

    public function __invoke(RevokeImpersonationRequest $request, string $audit): RedirectResponse
    {
        $operator = $this->manager->currentImpersonatorOrNull();

        $this->impersonations->revoke(
            auditId: $audit,
            revokedBy: $operator === null ? null : $this->manager->identities()->fromUser($operator),
            note: is_string($note = $request->input('note')) ? $note : null,
        );

        return back()->with(
            'impersonator_status',
            'Impersonation revoked. The session ends on its next request.',
        );
    }
}
