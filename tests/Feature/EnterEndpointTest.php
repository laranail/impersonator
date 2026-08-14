<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\Secret;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 5);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);
});

function postEnter(array $payload = []): TestResponse
{
    return test()->post(route('impersonator.enter'), $payload);
}

it('enters through the endpoint', function (): void {
    Auth::guard('web')->setUser($this->admin);

    postEnter(['target_type' => 'user', 'target_id' => (string) $this->target->getKey()])
        ->assertRedirect('/');

    expect(Impersonator::isImpersonating())->toBeTrue();
});

it('requires authentication', function (): void {
    postEnter(['target_type' => 'user', 'target_id' => '2'])->assertForbidden();
});

it('rejects a target type outside the allowlist', function (): void {
    // The control against arbitrary class injection, at the validation boundary.
    Auth::guard('web')->setUser($this->admin);

    postEnter(['target_type' => Secret::class, 'target_id' => '1'])
        ->assertSessionHasErrors('target_type');

    postEnter(['target_type' => 'App\\Models\\Anything', 'target_id' => '1'])
        ->assertSessionHasErrors('target_type');
});

it('rejects an unregistered mode with a 422 rather than a 500', function (): void {
    Auth::guard('web')->setUser($this->admin);

    postEnter([
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
        'mode' => 'god',
    ])->assertSessionHasErrors('mode');
});

it('accepts each registered mode', function (string $mode): void {
    Auth::guard('web')->setUser($this->admin);

    postEnter([
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
        'mode' => $mode,
    ])->assertRedirect();

    expect(Impersonator::mode()?->name)->toBe($mode);
})->with(['read_only', 'limited', 'full']);

it('rejects a guard that does not exist', function (): void {
    Auth::guard('web')->setUser($this->admin);

    postEnter([
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
        'guard' => 'nonexistent',
    ])->assertSessionHasErrors('guard');
});

it('rejects an open redirect', function (string $redirect): void {
    // An open redirect on an impersonation endpoint is a credential-phishing
    // primitive, so it is a validation failure rather than a silent fallback.
    Auth::guard('web')->setUser($this->admin);

    postEnter([
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
        'redirect_to' => $redirect,
    ])->assertSessionHasErrors('redirect_to');
})->with([
    'https://evil.example/phish',
    '//evil.example',
    '/\\evil.example',
    'javascript:alert(1)',
]);

it('honours a safe relative redirect', function (): void {
    Auth::guard('web')->setUser($this->admin);

    postEnter([
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
        'redirect_to' => '/dashboard',
    ])->assertRedirect('/dashboard');
});

it('requires a reason when configured to', function (): void {
    config()->set('laranail.impersonator.reason.require', true);
    Auth::guard('web')->setUser($this->admin);

    postEnter(['target_type' => 'user', 'target_id' => (string) $this->target->getKey()])
        ->assertSessionHasErrors('reason');
});

it('bounds the reason length', function (): void {
    config()->set('laranail.impersonator.reason.require', true);
    config()->set('laranail.impersonator.reason.max_length', 20);
    Auth::guard('web')->setUser($this->admin);

    postEnter([
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
        'reason' => str_repeat('x', 21),
    ])->assertSessionHasErrors('reason');
});

it('records the reason on the audit row', function (): void {
    Auth::guard('web')->setUser($this->admin);

    postEnter([
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
        'reason' => 'Ticket #4182',
    ]);

    expect(Impersonator::current()?->reason)->toBe('Ticket #4182');
});

it('404s for a target that does not exist', function (): void {
    Auth::guard('web')->setUser($this->admin);

    postEnter(['target_type' => 'user', 'target_id' => '99999'])->assertNotFound();
});

it('refuses self-impersonation through the endpoint too', function (): void {
    Auth::guard('web')->setUser($this->admin);

    postEnter(['target_type' => 'user', 'target_id' => (string) $this->admin->getKey()])
        ->assertForbidden();
});

it('marks the audit row as entered via http', function (): void {
    Auth::guard('web')->setUser($this->admin);

    postEnter(['target_type' => 'user', 'target_id' => (string) $this->target->getKey()]);

    $row = app(AuditStore::class)->find(Impersonator::current()->auditId);

    expect($row->metadata['entered_via'])->toBe('http');
});

it('revokes through the endpoint', function (): void {
    Auth::guard('web')->setUser($this->admin);
    postEnter(['target_type' => 'user', 'target_id' => (string) $this->target->getKey()]);
    $auditId = Impersonator::current()->auditId;

    $this->from('/admin')->post(route('impersonator.revoke', ['audit' => $auditId]))
        ->assertRedirect('/admin');

    expect(app(AuditStore::class)->find($auditId)->isRevoked())->toBeTrue();
});

it('rate limits enter attempts per operator, not per address', function (): void {
    // The risk being limited is one authorized person enumerating accounts, and they will do
    // it from a single address — so keying on the IP would rate-limit an office rather than
    // an operator.
    //
    // Probed with refused attempts, which is both the realistic scenario and the only way to
    // count repeatedly: a *successful* enter makes the operator the target, so the next
    // attempt would be refused as self-impersonation rather than throttled.
    config()->set('laranail.impersonator.rate_limiting.enter.attempts', 2);
    Auth::guard('web')->setUser($this->admin);

    $probe = ['target_type' => 'user', 'target_id' => '99999'];

    postEnter($probe)->assertNotFound();
    postEnter($probe)->assertNotFound();

    postEnter($probe)->assertStatus(429);
});

it('limits each operator separately', function (): void {
    config()->set('laranail.impersonator.rate_limiting.enter.attempts', 1);
    $other = User::create(['name' => 'Other admin']);
    $probe = ['target_type' => 'user', 'target_id' => '99999'];

    Auth::guard('web')->setUser($this->admin);
    postEnter($probe)->assertNotFound();
    postEnter($probe)->assertStatus(429);

    // A second operator has their own budget.
    Auth::guard('web')->setUser($other);
    postEnter($probe)->assertNotFound();
});
