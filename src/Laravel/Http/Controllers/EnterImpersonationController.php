<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Simtabi\Laranail\Impersonator\Laravel\Http\Requests\EnterImpersonationRequest;
use Simtabi\Laranail\Impersonator\Laravel\Services\ImpersonationService;
use Simtabi\Laranail\Impersonator\Laravel\Support\RedirectGuard;

/**
 * Starts an impersonation from a POST.
 *
 * Thin by design: validation lives in the Form Request, the decision in the policy, the
 * orchestration in the service. The controller's only job is turning an outcome into a
 * response — which is also why a cross-domain handoff is handled here, since only the
 * HTTP layer knows the difference between "go to this URL" and "you are now in".
 */
final readonly class EnterImpersonationController
{
    public function __construct(
        private ImpersonationService $impersonations,
        private RedirectGuard $redirects,
    ) {}

    public function __invoke(EnterImpersonationRequest $request): RedirectResponse
    {
        $outcome = $this->impersonations->enterRequest($request->toImpersonationRequest());

        // A pending handoff has not impersonated anybody yet; the operator has to
        // follow the URL for it to happen. `away` because it is a different host by
        // definition, and the token in it is single-use and short-lived.
        if ($outcome->pending) {
            return redirect()->away($outcome->acceptUrl());
        }

        return redirect()->to($this->redirects->afterEnter($outcome->redirectTo));
    }
}
