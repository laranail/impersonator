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
        return $this->harden(redirect()->to($this->redirects->afterEnter($outcome->redirectTo)));
    }

    /**
     * Keep the token in the URL from travelling any further than this request.
     *
     * A handoff token has to ride in the URL — the whole point is a link an operator follows on
     * another host — and a URL leaks in ways a request body does not: the `Referer` header on the
     * next navigation, browser history, and access logs at every proxy and CDN in between. The
     * short TTL and the single-use claim bound how long a leaked copy is worth anything; these two
     * headers reduce how many places it reaches in the first place.
     *
     * `no-referrer` is set rather than `same-origin` because the redirect target may be a different
     * host than the one that minted the link, and `same-origin` would still disclose the full URL
     * to it. `no-store` keeps the redirect out of the browser's back-forward cache and out of any
     * shared cache that would otherwise hold a URL containing a live credential.
     */
    private function harden(RedirectResponse $response): RedirectResponse
    {
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }
}
