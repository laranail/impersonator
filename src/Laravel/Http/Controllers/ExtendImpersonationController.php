<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Extends the current impersonation from inside it.
 *
 * POST, because it changes state — an extension reachable by GET could be triggered by a
 * prefetch or a pasted link, which would silently keep an impersonation alive that the
 * operator had finished with.
 *
 * A refusal is a 403 with the reason, not an exception page. The operator is inside a
 * customer's account when they see it, and "you have used all three extensions, this ends at
 * 14:32" is actionable where a stack trace is not. The code is the stable half of that
 * response and the message the translatable half, matching how the rest of the API reports
 * decisions.
 */
final readonly class ExtendImpersonationController
{
    public function __construct(private ImpersonationManager $impersonator) {}

    public function __invoke(Request $request): RedirectResponse|JsonResponse
    {
        $outcome = $this->impersonator->extendSession();

        if ($outcome->denied()) {
            // 403 rather than 409 or 422: every refusal here is ultimately "not permitted,
            // for this reason", whether the reason is a spent allowance, a withdrawn
            // permission or a revoked session. One status keeps clients from having to map
            // several onto the same handling.
            if ($request->expectsJson()) {
                return response()->json([
                    'message' => $outcome->grant->decision->reason,
                    'reason' => $outcome->grant->decision->code,
                ], 403);
            }

            throw new HttpException(403, (string) $outcome->grant->decision->reason);
        }

        if ($request->expectsJson()) {
            return response()->json($outcome->toArray());
        }

        return back()->with('impersonator_status', sprintf(
            'Impersonation extended by %d minutes.',
            (int) round($outcome->grant->seconds() / 60),
        ));
    }
}
