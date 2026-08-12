<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Simtabi\Laranail\Impersonator\Core\Support\ModeRegistry;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Providers\ImpersonatorServiceProvider;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;

it('merges the package config', function (): void {
    expect(config('impersonator.driver'))->toBe('session')
        ->and(config('impersonator.adapter'))->toBe('session')
        ->and(config('impersonator.tokens.bytes'))->toBe(40);
});

it('binds the manager as a singleton', function (): void {
    expect(app(ImpersonationManager::class))->toBe(app(ImpersonationManager::class));
});

it('binds the container alias, the helper and the facade to the same instance', function (): void {
    expect(app('impersonator'))->toBe(app(ImpersonationManager::class))
        ->and(impersonator())->toBe(app(ImpersonationManager::class))
        ->and(ImpersonatorFacade::getFacadeRoot())->toBe(app(ImpersonationManager::class));
});

it('shares one mode registry across the application', function (): void {
    // Custom modes registered by an app's own provider have to be visible to
    // every consumer of the manager, which only holds if the registry is shared.
    expect(app(ModeRegistry::class))->toBe(app(ModeRegistry::class))
        ->and(app(ImpersonationManager::class)->modes())->toBe(app(ModeRegistry::class));
});

it('binds the identity resolver', function (): void {
    expect(app(IdentityResolver::class))->toBeInstanceOf(IdentityResolver::class);
});

it('publishes the config under the documented tag', function (): void {
    $paths = ServiceProvider::pathsToPublish(ImpersonatorServiceProvider::class, 'impersonator-config');

    expect($paths)->toHaveCount(1)
        ->and(array_key_first($paths))->toEndWith('config/impersonator.php')
        ->and(reset($paths))->toEndWith('impersonator.php');
});

it('does not register the api routes by default', function (): void {
    // An impersonation API is a remote-control surface for every account in the system, so it is
    // something an operator switches on deliberately rather than something they acquire by
    // upgrading a package.
    expect(config('impersonator.api.enabled'))->toBeFalse()
        ->and(Route::has('impersonator.api.impersonations.store'))->toBeFalse()
        ->and(Route::has('impersonator.api.audits.index'))->toBeFalse();
});
