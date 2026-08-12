<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\StaffUser;

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('impersonator.targets.allowlist', ['user' => StaffUser::class]);
    config()->set('auth.providers.users.model', StaffUser::class);

    $this->admin = StaffUser::create(['name' => 'Admin']);
    $this->target = StaffUser::create(['name' => 'Customer']);

    $this->startSession();
});

it('enters through the model', function (): void {
    $outcome = $this->admin->impersonate($this->target);

    expect($outcome->isStarted())->toBeTrue()
        ->and(Auth::guard('web')->id())->toBe($this->target->getKey());
});

it('does not need an authenticated user, so it works from a job or a command', function (): void {
    // The impersonator is passed explicitly rather than read from the guard.
    expect(Auth::guard('web')->check())->toBeFalse()
        ->and($this->admin->impersonate($this->target)->isStarted())->toBeTrue();
});

it('passes the mode and reason through', function (): void {
    $outcome = $this->admin->impersonate($this->target, mode: Mode::full(), reason: 'Ticket #7');

    expect($outcome->session->mode->name)->toBe('full')
        ->and($outcome->session->reason)->toBe('Ticket #7');
});

it('reports impersonating state and the active mode', function (): void {
    $this->admin->impersonate($this->target);

    expect($this->admin->isImpersonating())->toBeTrue()
        ->and($this->admin->impersonationMode()?->name)->toBe('full');
});

it('identifies which user is being impersonated', function (): void {
    $this->admin->impersonate($this->target);

    expect($this->target->isBeingImpersonated())->toBeTrue()
        ->and($this->admin->isBeingImpersonated())->toBeFalse();
});

it('names the impersonator as the actor', function (): void {
    $this->admin->impersonate($this->target);

    expect($this->admin->impersonationActor()?->getKey())->toBe($this->admin->getKey());
});

it('leaves through the model', function (): void {
    $this->admin->impersonate($this->target);

    $session = $this->target->leaveImpersonation();

    expect($session)->not->toBeNull()
        ->and($this->admin->isImpersonating())->toBeFalse()
        ->and(Auth::guard('web')->id())->toBe($this->admin->getKey());
});

it('still runs the full authorization stack, so the trait cannot bypass it', function (): void {
    // A model method that decided its own permissions could be bypassed by calling
    // the manager directly — and vice versa. Both paths share one policy.
    expect(fn () => $this->admin->impersonate($this->admin))
        ->toThrow(ImpersonationDenied::class);
});

it('defaults both hooks to permissive so adding the trait changes nothing', function (): void {
    expect($this->admin->canImpersonate())->toBeTrue()
        ->and($this->admin->canBeImpersonated())->toBeTrue();
});
