<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Middleware;

use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/**
 * `throttle`, keyed on whoever is really making the request.
 *
 * Laravel's own `ThrottleRequests` keys on `$request->user()`, which during an impersonation is the
 * **target**. Two consequences, and both are worth avoiding:
 *
 *  - **The customer pays for the operator's traffic.** A support engineer working through an account
 *    consumes that customer's quota, so the customer can be rate-limited out of their own
 *    application by someone helping them.
 *  - **It is a denial-of-service primitive.** One authorised operator can deliberately exhaust a
 *    chosen customer's limit, and the request log will show the customer doing it to themselves.
 *
 * Keying on the operator fixes both and is also the more accurate answer: rate limits exist to bound
 * a *caller*, and the caller is the person who authenticated, not the account they are viewing.
 *
 * Drop-in for `throttle:…` — same arguments, same behaviour when nobody is impersonating, since
 * everything but the signature is inherited.
 *
 *   Route::middleware('laranail-impersonator.throttle:60,1')->group(…);
 *
 * For a named limiter defined with `RateLimiter::for()`, subclassing cannot help: the closure owns
 * the key. Use {@see ImpersonationManager::rateLimitKey()} inside it instead.
 */
class ThrottleByOperator extends ThrottleRequests
{
    /**
     * The rate-limit signature for this request.
     *
     * Falls through to the parent whenever no impersonation is active, so an application that swaps
     * this in globally gets identical behaviour on every ordinary request. Only the impersonated
     * ones differ, which is the entire point.
     */
    protected function resolveRequestSignature($request)
    {
        if (! $request instanceof Request) {
            return parent::resolveRequestSignature($request);
        }

        $operator = app(ImpersonationManager::class)->rateLimitKey($request);

        return $operator === null
            ? parent::resolveRequestSignature($request)
            : sha1($operator);
    }
}
