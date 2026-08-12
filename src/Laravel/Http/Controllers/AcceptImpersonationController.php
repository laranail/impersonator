<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Simtabi\Laranail\Impersonator\Laravel\Http\Requests\AcceptImpersonationRequest;
use Simtabi\Laranail\Impersonator\Laravel\Services\ImpersonationService;
use Simtabi\Laranail\Impersonator\Laravel\Support\RedirectGuard;

/**
 * Completes a cross-domain handoff.
 *
 * The one endpoint in the package reachable without an authenticated session, which is why
 * it is rate limited by IP and why the token does all the work. Everything the driver needs
 * — who is impersonating whom, in which mode — was fixed when the token was minted and is
 * re-authorized on redemption; nothing here is taken from the request beyond the token
 * itself.
 */
final readonly class AcceptImpersonationController
{
    public function __construct(
        private ImpersonationService $impersonations,
        private RedirectGuard $redirects,
    ) {}

    public function __invoke(AcceptImpersonationRequest $request, string $token): RedirectResponse
    {
        $outcome = $this->impersonations->complete($token, driver: 'token');

        // `to`, not `away`: the redirect lands inside the host we just authenticated on, and
        // the target came from the original caller, so it passes the redirect guard.
        return redirect()->to($this->redirects->afterEnter($outcome->redirectTo));
    }
}
