<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;

/*
| An operator authenticated on an `admin` guard entering, with the target logged
| in on `web`. This is the configuration where "leave" is ambiguous if the two
| guards are collapsed into one value, so it gets its own coverage.
*/

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('auth.providers.users.model', User::class);
    config()->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'users']);
    config()->set('laranail.impersonator.guards.impersonator', 'admin');
    config()->set('laranail.impersonator.guards.target', 'web');
    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    $this->startSession();
});

it('reads the impersonator from its own guard', function (): void {
    Auth::guard('admin')->setUser($this->admin);

    $outcome = Impersonator::enter($this->target);

    expect((string) $outcome->session->impersonator->id)->toBe((string) $this->admin->getKey())
        ->and($outcome->session->guards->impersonator)->toBe('admin')
        ->and($outcome->session->guards->target)->toBe('web');
});

it('logs the target in on the target guard only', function (): void {
    Auth::guard('admin')->setUser($this->admin);

    Impersonator::enter($this->target);

    expect(Auth::guard('web')->id())->toBe($this->target->getKey());
});

it('leaves the impersonator authenticated on their own guard throughout', function (): void {
    // The admin was never displaced, which is what makes leaving here a simple
    // logout of the target's guard rather than a restore.
    Auth::guard('admin')->setUser($this->admin);

    Impersonator::enter($this->target);

    expect(Auth::guard('admin')->id())->toBe($this->admin->getKey());
});

it('logs the target out on leave without touching the admin guard', function (): void {
    Auth::guard('admin')->setUser($this->admin);
    Impersonator::enter($this->target);

    Impersonator::leave();

    expect(Auth::guard('web')->check())->toBeFalse()
        ->and(Auth::guard('admin')->id())->toBe($this->admin->getKey())
        ->and(Impersonator::isImpersonating())->toBeFalse();
});

it('still reports the impersonator as the actor across guards', function (): void {
    Auth::guard('admin')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(Impersonator::actor()?->getKey())->toBe($this->admin->getKey());
});

it('refuses to use the session adapter against a token guard', function (): void {
    // A token guard cannot be logged in, so pairing it with this adapter is a
    // configuration error worth surfacing at selection rather than at use — and the
    // message has to name the guard, or the operator goes looking for a missing
    // composer package that was never the problem.
    config()->set('auth.guards.api', ['driver' => 'token', 'provider' => 'users']);
    config()->set('laranail.impersonator.guards.target', 'api');

    expect(fn () => Impersonator::adapter('session'))
        ->toThrow(ImpersonationException::class, 'configured guard [api]');
});
