<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Values\Credential;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthAdapter;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Contracts\ImpersonationDriver;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;

function fakeDriver(string $name, bool $available = true): ImpersonationDriver
{
    return new readonly class($name, $available) implements ImpersonationDriver
    {
        public function __construct(
            private string $name,
            private bool $available,
        ) {}

        public function name(): string
        {
            return $this->name;
        }

        public function isAvailable(): bool
        {
            return $this->available;
        }

        public function begin(ImpersonationRequest $request): ImpersonationOutcome
        {
            throw new ImpersonationException('not exercised here');
        }

        public function complete(string $token): ImpersonationOutcome
        {
            throw new ImpersonationException('not exercised here');
        }

        public function requiresHandoff(): bool
        {
            return false;
        }

        public function end(ImpersonationSession $session, EndReason $reason = EndReason::Left): void {}

        public function current(): ?ImpersonationSession
        {
            return null;
        }
    };
}

function fakeAdapter(string $name, bool $available = true): AuthAdapter
{
    return new readonly class($name, $available) implements AuthAdapter
    {
        public function __construct(
            private string $name,
            private bool $available,
        ) {}

        public function name(): string
        {
            return $this->name;
        }

        public function isAvailable(): bool
        {
            return $this->available;
        }

        public function authenticate(ImpersonationRequest $request, ImpersonationSession $session): Credential
        {
            return Credential::session('fake');
        }

        public function release(ImpersonationSession $session): void {}

        public function revoke(ImpersonationSession $session): bool
        {
            return false;
        }
    };
}

function manager(): ImpersonationManager
{
    return app(ImpersonationManager::class);
}

it('resolves a registered driver', function (): void {
    manager()->extend('fake', static fn (): ImpersonationDriver => fakeDriver('fake'));

    expect(manager()->driver('fake')->name())->toBe('fake');
});

it('caches a resolved driver rather than rebuilding it', function (): void {
    $built = 0;

    manager()->extend('fake', function () use (&$built): ImpersonationDriver {
        $built++;

        return fakeDriver('fake');
    });

    manager()->driver('fake');
    manager()->driver('fake');

    expect($built)->toBe(1);
});

it('does not construct a driver until it is asked for', function (): void {
    // An installation with Passport present but configured to `session` must
    // never construct the Passport adapter.
    $built = false;

    manager()->extend('lazy', function () use (&$built): ImpersonationDriver {
        $built = true;

        return fakeDriver('lazy');
    });

    expect($built)->toBeFalse();
});

it('fails loudly on an unknown driver, naming what is available', function (): void {
    manager()->extend('session', static fn (): ImpersonationDriver => fakeDriver('session'));

    expect(fn (): ImpersonationDriver => manager()->driver('nope'))
        ->toThrow(ImpersonationException::class, 'Available drivers: session');
});

it('refuses a registered but unavailable driver instead of degrading to another', function (): void {
    manager()->extend('tenancy', static fn (): ImpersonationDriver => fakeDriver('tenancy', available: false));

    expect(fn (): ImpersonationDriver => manager()->driver('tenancy'))
        ->toThrow(ImpersonationException::class, 'not available in this installation');
});

it('resolves the configured driver by default', function (): void {
    config()->set('laranail.impersonator.driver', 'session');
    manager()->extend('session', static fn (): ImpersonationDriver => fakeDriver('session'));

    expect(manager()->driver()->name())->toBe('session');
});

it('resolves auto to session when no tenant is initialized', function (): void {
    config()->set('laranail.impersonator.driver', 'auto');

    expect(manager()->defaultDriver())->toBe('session');
});

it('never second-guesses an explicit driver', function (): void {
    config()->set('laranail.impersonator.driver', 'token');

    expect(manager()->defaultDriver())->toBe('token');
});

it('composes the two axes independently', function (): void {
    // Drivers and adapters know nothing about each other, which is what makes
    // `token` + `sanctum` work without anyone having written that pairing.
    config()->set('laranail.impersonator.driver', 'token');
    config()->set('laranail.impersonator.adapter', 'sanctum');

    manager()->extend('token', static fn (): ImpersonationDriver => fakeDriver('token'));
    manager()->extendAdapter('sanctum', static fn (): AuthAdapter => fakeAdapter('sanctum'));

    expect(manager()->driver()->name())->toBe('token')
        ->and(manager()->adapter()->name())->toBe('sanctum');
});

it('refuses an adapter whose package is absent', function (): void {
    manager()->extendAdapter('passport', static fn (): AuthAdapter => fakeAdapter('passport', available: false));

    expect(fn (): AuthAdapter => manager()->adapter('passport'))
        ->toThrow(ImpersonationException::class, 'not available');
});

it('reports availability without throwing, for the doctor command', function (): void {
    manager()->extend('ok', static fn (): ImpersonationDriver => fakeDriver('ok'));
    manager()->extend('down', static fn (): ImpersonationDriver => fakeDriver('down', available: false));
    manager()->extend('broken', static function (): ImpersonationDriver {
        throw new RuntimeException('cannot build');
    });

    $availability = manager()->driverAvailability();

    expect($availability)->toHaveKey('session')
        ->and(array_intersect_key($availability, array_flip(['ok', 'down', 'broken'])))
        ->toBe(['ok' => true, 'down' => false, 'broken' => false]);
});

it('lets a later registration replace a built-in of the same name', function (): void {
    manager()->extend('session', static fn (): ImpersonationDriver => fakeDriver('original'));
    manager()->driver('session');
    manager()->extend('session', static fn (): ImpersonationDriver => fakeDriver('replacement'));

    expect(manager()->driver('session')->name())->toBe('replacement');
});

it('reads the guard pair from config, allowing distinct guards per side', function (): void {
    config()->set('laranail.impersonator.guards.impersonator', 'admin');
    config()->set('laranail.impersonator.guards.target', 'web');

    $guards = manager()->guards();

    expect($guards->impersonator)->toBe('admin')
        ->and($guards->target)->toBe('web')
        ->and($guards->areSame())->toBeFalse();
});

it('reports no active impersonation when the driver cannot even be built', function (): void {
    // A misconfigured driver must not break a Blade directive on every page.
    config()->set('laranail.impersonator.driver', 'missing');

    expect(manager()->current())->toBeNull()
        ->and(manager()->isImpersonating())->toBeFalse();
});
