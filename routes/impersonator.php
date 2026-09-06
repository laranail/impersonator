<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\EnterImpersonationController;
use Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\LeaveImpersonationController;
use Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\AcceptImpersonationController;
use Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\ExtendImpersonationController;
use Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\RevokeImpersonationController;

/*
| The package's own routes.
|
| `leave` is registered whenever routes are registered at all, because leaving has to be
| reachable from an impersonated session regardless of driver — an operator who cannot
| leave is stuck inside a customer's account.
|
| `enter` and `revoke` are POST: both change state, so neither may be a GET that a
| crawler, a prefetcher or a pasted URL can trigger.
*/

Route::middleware(config('laranail.impersonator.routes.middleware', ['web']))
    ->prefix(config('laranail.impersonator.routes.prefix', 'impersonator'))
    ->name(config('laranail.impersonator.routes.name_prefix', 'impersonator.'))
    ->group(function (): void {
        Route::post(config('laranail.impersonator.routes.enter_path', 'enter'), EnterImpersonationController::class)
            ->middleware('throttle:impersonator-enter')
            ->name('enter');

        Route::get(config('laranail.impersonator.routes.leave_path', 'leave'), LeaveImpersonationController::class)
            ->name('leave');

        // Registered alongside `leave` and for a related reason: both have to be reachable
        // from inside an impersonated session. Throttled on the enter limiter — which is
        // keyed per operator — because extending is the same kind of privileged act as
        // entering, and an unbounded extend endpoint is a way to hammer the audit table.
        Route::post(config('laranail.impersonator.routes.extend_path', 'extend'), ExtendImpersonationController::class)
            ->middleware('throttle:impersonator-enter')
            ->name('extend');

        Route::post(config('laranail.impersonator.routes.revoke_path', 'revoke/{audit}'), RevokeImpersonationController::class)
            ->name('revoke');

        // The one endpoint reachable without an authenticated session — by design, since a
        // handoff exists precisely because the caller's session does not reach this host.
        // The token is the credential, so this is throttled by IP.
        Route::get(config('laranail.impersonator.routes.accept_path', 'accept/{token}'), AcceptImpersonationController::class)
            ->middleware('throttle:impersonator-accept')
            ->name('accept');
    });
