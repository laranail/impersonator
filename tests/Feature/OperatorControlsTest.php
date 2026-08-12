<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\GuardImpersonationLifetime;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\RbacUser;

/*
| The operator-side controls: step-up, idle timeout, per-request re-authorization, target eligibility.
|
| Each is off by default, because each can refuse an impersonation an installation expects to work.
| That default is itself asserted — a control that switched itself on during an upgrade would break
| support workflows at the worst moment.
*/

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->boolean('blocked')->default(false);
        $table->json('roles')->nullable();
        $table->json('permissions')->nullable();
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('impersonator.targets.allowlist', ['user' => RbacUser::class]);
    config()->set('auth.providers.users.model', RbacUser::class);
    config()->set('impersonator.limits.state_cache.ttl', 0);

    $this->admin = RbacUser::create([
        'name' => 'Admin',
        'roles' => ['admin'],
        'permissions' => ['impersonator.enter', 'impersonator.mode.full'],
    ]);
    $this->target = RbacUser::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

it('leaves every control off by default', function (): void {
    // A control that turned itself on during an upgrade would refuse impersonations an installation
    // expects to work — at the moment somebody is trying to help a customer.
    expect(config('impersonator.authorization.step_up.require'))->toBeFalse()
        ->and(config('impersonator.authorization.recheck_each_request'))->toBeFalse()
        ->and(config('impersonator.limits.max_idle'))->toBeNull()
        ->and(config('impersonator.targets.eligibility'))->toBeNull();

    expect(Impersonator::enter($this->target)->isStarted())->toBeTrue();
});

it('refuses to enter without a recent password confirmation', function (): void {
    config()->set('impersonator.authorization.step_up.require', true);

    try {
        Impersonator::enter($this->target);
        $this->fail('entered without confirming');
    } catch (ImpersonationDenied $e) {
        expect($e->code())->toBe(Decision::STEP_UP_REQUIRED);
    }
});

it('refuses on a stale confirmation as well as an absent one', function (): void {
    // Absent is the more important half: an install that forgot the host-side flow produces exactly
    // that, and treating it as passing would make the control decorative.
    config()->set('impersonator.authorization.step_up.require', true);
    config()->set('impersonator.authorization.step_up.within', 60);

    session()->put('auth.password_confirmed_at', time() - 3600);

    expect(fn () => Impersonator::enter($this->target))->toThrow(ImpersonationDenied::class);

    session()->put('auth.password_confirmed_at', time() - 10);

    expect(Impersonator::enter($this->target)->isStarted())->toBeTrue();
});

it('ends an impersonation that sat idle', function (): void {
    config()->set('impersonator.limits.max_idle', 5);

    Route::middleware(['web', GuardImpersonationLifetime::class])->get('/app/inside', fn (): string => 'ok');

    Impersonator::enter($this->target);

    // First request stamps activity; an absent stamp must not read as infinitely old, or every
    // impersonation would die on its second request.
    $this->get('/app/inside')->assertOk();

    $this->travel(3)->minutes();
    $this->get('/app/inside')->assertOk();

    // Working continuously restarts the clock, so total elapsed time is past the cap and it survives.
    $this->travel(3)->minutes();
    $this->get('/app/inside')->assertOk();
    expect(Impersonator::isImpersonating())->toBeTrue();

    $this->travel(6)->minutes();
    $this->get('/app/inside')->assertRedirect();
    expect(Impersonator::isImpersonating())->toBeFalse();
});

it('ends a live impersonation when the operator loses their permission', function (): void {
    // The policy runs at enter, so without this a revoked role leaves live sessions running until the
    // duration cap — the withdrawal that mattered most taking effect last.
    config()->set('impersonator.authorization.policy', RbacPolicy::class);
    config()->set('impersonator.authorization.recheck_each_request', true);

    Route::middleware(['web', GuardImpersonationLifetime::class])->get('/app/inside', fn (): string => 'ok');

    Impersonator::enter($this->target);
    $this->get('/app/inside')->assertOk();

    // The role is withdrawn mid-session.
    $this->admin->forceFill(['permissions' => []])->save();

    $this->get('/app/inside')->assertRedirect();
    expect(Impersonator::isImpersonating())->toBeFalse();
});

it('leaves a live impersonation alone when the recheck is off', function (): void {
    config()->set('impersonator.authorization.policy', RbacPolicy::class);
    config()->set('impersonator.authorization.recheck_each_request', false);

    Route::middleware(['web', GuardImpersonationLifetime::class])->get('/app/inside', fn (): string => 'ok');

    Impersonator::enter($this->target);
    $this->admin->forceFill(['permissions' => []])->save();

    // Documented behaviour, not an oversight: the check costs a permission lookup per request.
    $this->get('/app/inside')->assertOk();
    expect(Impersonator::isImpersonating())->toBeTrue();
});

it('refuses a target an application rules ineligible', function (): void {
    // The allowlist answers which models; this answers which instances — blocked, suspended, internal.
    // `(bool)`, not `!== true`: the column is uncast on this fixture, so SQLite hands back `1` and a
    // strict comparison would let every blocked account through. Worth spelling out — a rule written
    // that way in an application would fail open silently, which is the one direction that matters.
    config()->set('impersonator.targets.eligibility', fn (object $target): bool => ! (bool) $target->blocked);

    $this->target->forceFill(['blocked' => true])->save();

    try {
        Impersonator::enter($this->target);
        $this->fail('entered a blocked account');
    } catch (ImpersonationDenied $e) {
        expect($e->code())->toBe(Decision::TARGET_NOT_ELIGIBLE);
    }
});

it('fails closed when an eligibility rule returns something other than true or throws', function (): void {
    foreach (['yes', 1, null, []] as $value) {
        config()->set('impersonator.targets.eligibility', fn (): mixed => $value);

        expect(fn () => Impersonator::enter($this->target))->toThrow(ImpersonationDenied::class);
    }

    config()->set('impersonator.targets.eligibility', function (): bool {
        throw new RuntimeException('the directory is down');
    });

    expect(fn () => Impersonator::enter($this->target))->toThrow(ImpersonationDenied::class);
});
