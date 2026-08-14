<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

/*
| Rate limits must bound the caller, and while impersonating the caller is the operator.
|
| Laravel's `ThrottleRequests` keys on `$request->user()`, which is the target. That bills an
| operator's traffic to the customer's quota — so a support engineer can rate-limit a customer out of
| their own application, and an operator can do it to a chosen customer deliberately.
*/

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('impersonator.limits.max_active_per_impersonator', 5);
    config()->set('impersonator.limits.state_cache.ttl', 0);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    $this->startSession();
});

it('reports no key when nobody is impersonating', function (): void {
    // Null rather than a fabricated key, so a caller can fall through to whatever it would
    // otherwise have used.
    Auth::guard('web')->setUser($this->admin);

    expect(app(ImpersonationManager::class)->rateLimitKey(request()))->toBeNull();
});

it('keys on the operator while impersonating, not the target', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    $key = app(ImpersonationManager::class)->rateLimitKey(request());

    expect($key)->toContain((string) $this->admin->getKey())
        ->and($key)->not->toContain('user:' . $this->target->getKey());
});

it('qualifies the key by morph type so two models sharing an id do not share a bucket', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(app(ImpersonationManager::class)->rateLimitKey(request()))
        ->toBe('impersonator-operator:user:' . $this->admin->getKey());
});

it('spends the operator budget rather than the target budget', function (): void {
    // The behavioural assertion. Two impersonated requests through the drop-in middleware must
    // consume the operator's allowance; the target's must be untouched.
    Route::middleware(['web', 'laranail-impersonator.throttle:1,1'])
        ->get('/app/limited', fn (): string => 'ok')
        ->name('limited');

    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    $this->get('/app/limited')->assertOk();
    $this->get('/app/limited')->assertStatus(429);

    // Now leave and hit it as the target themselves. Under Laravel's own keying the operator's two
    // attempts would already have exhausted this; keyed on the operator, the customer is unaffected.
    Impersonator::leave();
    Auth::guard('web')->setUser($this->target);

    $this->get('/app/limited')->assertOk();
});

it('behaves exactly like throttle when nobody is impersonating', function (): void {
    Route::middleware(['web', 'laranail-impersonator.throttle:1,1'])
        ->get('/app/plain', fn (): string => 'ok');

    Auth::guard('web')->setUser($this->admin);

    $this->get('/app/plain')->assertOk();
    $this->get('/app/plain')->assertStatus(429);
});
