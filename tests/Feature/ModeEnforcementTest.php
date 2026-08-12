<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Events\ModeViolationBlocked;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\EnforceImpersonationMode;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\GuardImpersonationLifetime;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

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

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    // A miniature host application behind the enforcement middleware.
    Route::middleware(['web', GuardImpersonationLifetime::class, EnforceImpersonationMode::class])
        ->group(function (): void {
            Route::get('/app/orders', fn (): string => 'orders')->name('orders.index');

            // Every unsafe verb on one path, so routing cannot 405 before the
            // middleware gets a chance to refuse — otherwise the test would pass for
            // the wrong reason.
            Route::match(['post', 'put', 'patch', 'delete'], '/app/orders', fn (): string => 'written')
                ->name('orders.store');
            Route::delete('/app/account', fn (): string => 'gone')->name('profile.destroy');
            Route::post('/billing/card', fn (): string => 'charged')->name('billing.card');
            Route::get('/app/sneaky-write', function (): string {
                User::query()->where('id', 1)->update(['name' => 'changed via GET']);

                return 'written';
            });
        });

    $this->startSession();
});

function impersonateAs(User $admin, User $target, string $mode): void
{
    Auth::guard('web')->setUser($admin);
    Impersonator::enter($target, mode: $mode);
}

// ── read_only ───────────────────────────────────────────────────────────────

it('allows reads in read_only mode', function (): void {
    impersonateAs($this->admin, $this->target, 'read_only');

    $this->get('/app/orders')->assertOk();
});

it('refuses every unsafe method in read_only mode', function (string $method): void {
    impersonateAs($this->admin, $this->target, 'read_only');

    $this->call($method, '/app/orders')->assertForbidden();
})->with(['POST', 'PUT', 'PATCH', 'DELETE']);

it('keeps the leave route reachable in read_only mode', function (): void {
    // A mode that could trap an operator inside an account would be worse than no
    // mode at all.
    impersonateAs($this->admin, $this->target, 'read_only');

    $this->get(route('impersonator.leave'))->assertRedirect();
    expect(Impersonator::isImpersonating())->toBeFalse();
});

it('emits a violation event carrying the decision', function (): void {
    // One refusal is a misclick; several in a row is somebody probing the boundary,
    // and that distinction only exists if each is observable.
    Event::fake([ModeViolationBlocked::class]);
    impersonateAs($this->admin, $this->target, 'read_only');

    $this->post('/app/orders')->assertForbidden();

    Event::assertDispatched(
        ModeViolationBlocked::class,
        static fn (ModeViolationBlocked $e): bool => $e->decision->code === 'mode_forbids_write'
            && $e->action->normalizedMethod() === 'POST',
    );
});

it('does not leak internal detail into the refusal', function (): void {
    impersonateAs($this->admin, $this->target, 'read_only');

    $response = $this->post('/app/orders');

    expect($response->getContent())->not->toContain('Simtabi\\')
        ->and($response->getContent())->not->toContain('vendor/');
});

it('catches a write hidden behind a GET when prevent_writes is on', function (): void {
    // HTTP-method checking cannot see this; only a persistence-level guard can.
    config()->set('impersonator.modes.read_only.prevent_writes', true);
    impersonateAs($this->admin, $this->target, 'read_only');

    $this->get('/app/sneaky-write')->assertForbidden();

    expect(User::find(1)?->name)->not->toBe('changed via GET');
});

it('permits the hidden write when prevent_writes is off', function (): void {
    // Documented gap, and the reason the stricter net exists as an option.
    config()->set('impersonator.modes.read_only.prevent_writes', false);
    impersonateAs($this->admin, $this->target, 'read_only');

    $this->get('/app/sneaky-write')->assertOk();
});

// ── limited ─────────────────────────────────────────────────────────────────

it('allows an ordinary write in limited mode', function (): void {
    impersonateAs($this->admin, $this->target, 'limited');

    $this->post('/app/orders')->assertOk();
});

it('refuses a deny-listed route name in limited mode', function (): void {
    impersonateAs($this->admin, $this->target, 'limited');

    $this->delete('/app/account')->assertForbidden();
});

it('refuses a deny-listed path pattern in limited mode', function (): void {
    // Matched on the path rather than the route name, because the same protected
    // operation is reachable by differently-named routes in different applications.
    impersonateAs($this->admin, $this->target, 'limited');

    $this->post('/billing/card')->assertForbidden();
});

it('still allows reads of a deny-listed area in limited mode', function (): void {
    // This mode narrows what can be changed, not what can be read.
    impersonateAs($this->admin, $this->target, 'limited');

    $this->get('/app/orders')->assertOk();
});

// ── full ────────────────────────────────────────────────────────────────────

it('allows everything in full mode', function (): void {
    impersonateAs($this->admin, $this->target, 'full');

    $this->post('/app/orders')->assertOk();
    $this->delete('/app/account')->assertOk();
});

it('enforces nothing when not impersonating', function (): void {
    Auth::guard('web')->setUser($this->admin);

    $this->post('/app/orders')->assertOk();
    $this->delete('/app/account')->assertOk();
});

// ── mode tampering ──────────────────────────────────────────────────────────

it('ignores a mode supplied as request input', function (): void {
    // The whole mechanism: the mode is server-side state, so there is no header,
    // parameter or cookie a client can set to widen its own envelope.
    impersonateAs($this->admin, $this->target, 'read_only');

    $this->post('/app/orders', ['mode' => 'full'])->assertForbidden();
    $this->withHeaders(['X-Impersonation-Mode' => 'full'])->post('/app/orders')->assertForbidden();
    $this->get('/app/orders?mode=full')->assertOk();

    expect(Impersonator::mode()?->name)->toBe('read_only');
});
