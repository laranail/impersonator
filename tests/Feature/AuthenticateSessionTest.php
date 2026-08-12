<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Session\Middleware\AuthenticateSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

/*
| Impersonating underneath Laravel's own `auth.session` middleware.
|
| `AuthenticateSession` keeps a hash of the authenticated user's password in the session and compares
| it every request. A mismatch reads as a stolen session: logout, flush, throw. Switching the
| authenticated user without moving that sentinel therefore logs the *operator* out of their own
| account — and the sentinel is keyed on `auth.defaults.guard` rather than the guard in use, so a
| multi-guard setup is where it bites.
|
| This interaction had no coverage at all before. It is the mechanism behind several long-standing
| bug reports against other impersonation packages.
*/

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->string('password')->nullable();
        $table->string('remember_token', 100)->nullable();
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('impersonator.limits.max_active_per_impersonator', 5);
    config()->set('impersonator.limits.state_cache.ttl', 0);

    $this->admin = User::create(['name' => 'Admin', 'password' => bcrypt('operator-secret')]);
    $this->target = User::create(['name' => 'Customer', 'password' => bcrypt('customer-secret')]);

    // A host route behind the real middleware, which is the only way this is observable.
    Route::middleware(['web', AuthenticateSession::class])
        ->get('/app/guarded', fn (): string => 'ok')
        ->name('guarded');

    $this->startSession();
});

function sentinel(): ?string
{
    $value = session()->get('password_hash_' . config('auth.defaults.guard'));

    return is_string($value) ? $value : null;
}

it('moves the session password sentinel to the target on enter', function (): void {
    Auth::guard('web')->setUser($this->admin);

    Impersonator::enter($this->target);

    // Not the operator's any more. If it were, the next request through auth.session would log them
    // out and flush the session.
    expect(sentinel())->not->toBeNull()
        ->and(Auth::guard('web')->id())->toBe($this->target->getKey());
});

it('keeps the operator signed in through a guarded request while impersonating', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    $this->get('/app/guarded')->assertOk();

    expect(Impersonator::isImpersonating())->toBeTrue();
});

it('restores the sentinel on leave so the operator survives the next request', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);
    Impersonator::leave();

    $this->get('/app/guarded')->assertOk();

    expect(Auth::guard('web')->id())->toBe($this->admin->getKey())
        ->and(Impersonator::isImpersonating())->toBeFalse();
});

it('survives a guarded request with the session flush disabled', function (): void {
    // The case that actually reproduces the bug, and the sequence matters.
    //
    // The sentinel has to already hold the *operator's* hash before the switch, which only happens
    // once they have been through the middleware themselves. Impersonating straight after
    // `setUser()` leaves no sentinel at all, so the middleware seeds it from the target and nothing
    // ever mismatches — a test written that way passes with or without the fix.
    //
    // Flushing the session masks it too, for the same reason, so the opt-out is off here.
    config()->set('impersonator.session.flush_on_switch', false);

    Auth::guard('web')->setUser($this->admin);

    // Seeds `password_hash_web` with the operator's hash.
    $this->get('/app/guarded')->assertOk();
    $operatorSentinel = sentinel();
    expect($operatorSentinel)->not->toBeNull();

    Impersonator::enter($this->target);

    // Without the sync the sentinel still holds the operator's hash while the target is
    // authenticated, and this request logs the operator out and flushes the session.
    $this->get('/app/guarded')->assertOk();

    expect(sentinel())->not->toBe($operatorSentinel)
        ->and(Impersonator::isImpersonating())->toBeTrue()
        ->and(Auth::guard('web')->id())->toBe($this->target->getKey());
});

it('survives leaving after a guarded request, with the flush disabled', function (): void {
    // The return leg of the same problem: on leave the sentinel holds the target's hash while the
    // operator is authenticated again.
    config()->set('impersonator.session.flush_on_switch', false);

    Auth::guard('web')->setUser($this->admin);
    $this->get('/app/guarded')->assertOk();

    Impersonator::enter($this->target);
    $this->get('/app/guarded')->assertOk();

    Impersonator::leave();

    $this->get('/app/guarded')->assertOk();

    expect(Impersonator::isImpersonating())->toBeFalse()
        ->and(Auth::guard('web')->id())->toBe($this->admin->getKey());
});

it('leaves no stale sentinel for a passwordless target', function (): void {
    // auth.session skips the comparison entirely when the user has no password, so the correct
    // state is no sentinel rather than one still belonging to the operator.
    $passwordless = User::create(['name' => 'SSO Only', 'password' => null]);

    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($passwordless);

    expect(sentinel())->toBeNull();
});
