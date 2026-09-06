<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\RedirectGuard;

/**
 * Ends the current impersonation.
 *
 * Deliberately the least defended endpoint in the package, because leaving only
 * ever de-escalates. It requires no permission and no mode allowance — an
 * operator who has somehow lost the right to impersonate must still be able to
 * stop, and every mode allowlists this route for the same reason.
 *
 * The only precondition is that an impersonation is actually active, so a stray
 * request cannot log somebody out of their own account.
 */
final readonly class LeaveImpersonationController
{
    public function __construct(
        private ImpersonationManager $impersonator,
        private RedirectGuard $redirects,
    ) {}

    public function __invoke(): RedirectResponse
    {
        if (! $this->impersonator->isImpersonating()) {
            throw new HttpException(403, 'There is no active impersonation to leave.');
        }

        $session = $this->impersonator->leave(EndReason::Left);

        // A per-impersonation destination recorded at enter time, if one was given.
        // It still passes through the redirect guard: metadata originates from the
        // caller who started the impersonation, so it is no more trusted than a
        // query parameter would be.
        $requested = $session?->metadata['leave_redirect'] ?? null;

        return redirect()->to($this->redirects->afterLeave(
            is_string($requested) ? $requested : null,
        ));
    }
}
