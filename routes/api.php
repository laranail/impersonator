<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\Api\ApprovalController;
use Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\Api\AuditController;
use Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\Api\ImpersonationController;

/*
| The REST API. Registered only when `impersonator.api.enabled` is true — off by default, because an
| impersonation API is a remote-control surface for every account in the system and nobody should get
| one by upgrading a package.
|
| Versioned in the prefix rather than by header, so a breaking change can ship alongside the old
| shape instead of coordinating every client at once.
|
| The middleware stack is configurable and defaults to `auth:sanctum`. Its second job is the RBAC
| permission: entering, revoking and reading the trail are three separate permissions, checked by the
| AuthorizationPolicy inside the actions rather than declared here — so the API and the HTML endpoints
| cannot drift.
*/

Route::middleware(config('impersonator.api.middleware', ['api', 'auth:sanctum']))
    ->prefix(config('impersonator.api.prefix', 'impersonator/api/v1'))
    ->name(config('impersonator.api.name_prefix', 'impersonator.api.'))
    ->group(function (): void {
        Route::post('impersonations', [ImpersonationController::class, 'store'])
            ->middleware('throttle:impersonator-api')
            ->name('impersonations.store');

        Route::get('impersonations/current', [ImpersonationController::class, 'current'])
            ->name('impersonations.current');

        Route::delete('impersonations/current', [ImpersonationController::class, 'destroy'])
            ->name('impersonations.destroy');

        Route::post('impersonations/{audit}/revoke', [ImpersonationController::class, 'revoke'])
            ->middleware('throttle:impersonator-api')
            ->name('impersonations.revoke');

        Route::get('audits', [AuditController::class, 'index'])->name('audits.index');
        Route::get('audits/{audit}', [AuditController::class, 'show'])->name('audits.show');
        Route::get('audits/{audit}/export', [AuditController::class, 'export'])->name('audits.export');

        // The break-glass queue. Note there is no `POST /approvals`: a request is opened by
        // `POST /impersonations` once the authorization stack has passed, so an operator cannot
        // queue a request for an account they were never allowed to reach.
        //
        // `mine` is declared before `{approval}` so the literal segment is not swallowed by the
        // parameter — a caller asking for their own requests would otherwise get a 404 for an
        // approval whose id happened to be "mine".
        Route::get('approvals', [ApprovalController::class, 'index'])->name('approvals.index');
        Route::get('approvals/mine', [ApprovalController::class, 'mine'])->name('approvals.mine');
        Route::get('approvals/{approval}', [ApprovalController::class, 'show'])->name('approvals.show');

        Route::post('approvals/{approval}/grant', [ApprovalController::class, 'grant'])
            ->middleware('throttle:impersonator-api')
            ->name('approvals.grant');

        Route::post('approvals/{approval}/deny', [ApprovalController::class, 'deny'])
            ->middleware('throttle:impersonator-api')
            ->name('approvals.deny');
    });
