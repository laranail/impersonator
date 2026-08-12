<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\TrailStore;
use Simtabi\Laranail\Impersonator\Core\Events\ModeViolationBlocked;
use Simtabi\Laranail\Impersonator\Core\Support\ModeRegistry;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\EnforceImpersonationMode;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\GuardImpersonationLifetime;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\RecordImpersonationTrail;
use Simtabi\Laranail\Impersonator\Laravel\Support\PersistenceGuard;
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

it('catches a write hidden behind a GET by default', function (): void {
    // No config here on purpose: the persistence guard is on out of the box. A mode named
    // read_only that permits a write behind a GET route is not read-only, and this is the
    // property the whole mode exists to provide.
    impersonateAs($this->admin, $this->target, 'read_only');

    $this->get('/app/sneaky-write')->assertForbidden();

    expect(User::find(1)?->name)->not->toBe('changed via GET');
});

it('ships with the persistence guard enabled', function (): void {
    // Pins the default itself, not just the behaviour. Shipping this off would silently
    // reduce read_only to an HTTP-method check, which is a much weaker promise than the
    // name and the documentation make.
    expect(config('impersonator.modes.read_only.prevent_writes'))->toBeTrue()
        ->and(app(ModeRegistry::class)->enforcer(Mode::of('read_only'))->guardsPersistence())->toBeTrue();
});

it('permits the hidden write only when the guard is explicitly disabled', function (): void {
    // The escape hatch, for an application with a specific incompatibility. Turning it off
    // means read_only bounds HTTP methods alone.
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

// ── the persistence guard must not outlive its request ──────────────────────

it('lets an operator leave after a read-only request', function (): void {
    // The regression this exists for: `DB::beforeExecuting` has no removal counterpart, so a
    // per-request guard stayed armed after the response — and closing an impersonation is an
    // UPDATE on the audit row. The read-only guard denied it and the operator was trapped inside
    // the customer's account, which is the one outcome the mode must never produce.
    impersonateAs($this->admin, $this->target, 'read_only');

    $this->get('/app/orders')->assertOk();

    Impersonator::leave();

    expect(Impersonator::isImpersonating())->toBeFalse()
        ->and(Auth::guard('web')->id())->toBe($this->admin->getKey());
});

it('disarms the guard even when the request throws', function (): void {
    impersonateAs($this->admin, $this->target, 'read_only');

    // A refused write aborts the request; the guard still has to come off.
    $this->post('/app/orders')->assertForbidden();

    expect(app(PersistenceGuard::class)->armed())->toBeFalse();

    // And a subsequent write outside any request is unaffected.
    Impersonator::leave();

    expect(Impersonator::isImpersonating())->toBeFalse();
});

it('stops enforcing a mode once its request is over', function (): void {
    impersonateAs($this->admin, $this->target, 'read_only');
    $this->get('/app/orders')->assertOk();

    // Nothing is armed between requests, so a stale session cannot keep enforcing.
    expect(app(PersistenceGuard::class)->armed())->toBeFalse()
        ->and(app(PersistenceGuard::class)->session())->toBeNull();
});

it('never blocks its own audit and trail writes', function (): void {
    // The package's bookkeeping is not the impersonated user's action. If a mode blocked it, the
    // record that makes the mode auditable would be the first casualty.
    Route::middleware(['web', EnforceImpersonationMode::class, RecordImpersonationTrail::class])
        ->get('/app/trailed', fn (): string => 'ok');

    impersonateAs($this->admin, $this->target, 'read_only');

    $this->get('/app/trailed')->assertOk();

    expect(app(TrailStore::class)->countForAudit(Impersonator::current()->auditId))->toBe(1);
});

it('never blocks the framework session and cache tables', function (): void {
    // With SESSION_DRIVER=database every request updates a row. Judging that as a user write would
    // make read_only refuse every page it is supposed to allow.
    impersonateAs($this->admin, $this->target, 'read_only');

    // Behavioural rather than structural: a write to the sessions table passes the armed guard.
    $guard = app(PersistenceGuard::class);
    $guard->arm(
        Impersonator::current(),
        app(ModeRegistry::class)->enforcer(Mode::of('read_only')),
        'app/orders',
        ['sessions', 'impersonator_audits'],
    );

    expect($guard->inspect('update "sessions" set "payload" = ? where "id" = ?'))->toBeNull()
        ->and($guard->inspect('insert into "impersonator_audits" ("id") values (?)'))->toBeNull()
        ->and($guard->inspect('select * from "users"'))->toBeNull();

    $denied = $guard->inspect('update "users" set "name" = ? where "id" = ?');
    expect($denied)->not->toBeNull()->and($denied->denied())->toBeTrue();

    $guard->disarm();
});

it('blocks a job dispatched from a read-only session', function (): void {
    // A queued write is still a write. Exempting the queue tables would be a laundering route
    // around the whole boundary, so they are deliberately not exempt.
    impersonateAs($this->admin, $this->target, 'read_only');

    $guard = app(PersistenceGuard::class);
    $guard->arm(
        Impersonator::current(),
        app(ModeRegistry::class)->enforcer(Mode::of('read_only')),
        'app/orders',
        ['sessions'],
    );

    $decision = $guard->inspect('insert into "jobs" ("queue", "payload") values (?, ?)');

    expect($decision)->not->toBeNull()->and($decision->denied())->toBeTrue();

    $guard->disarm();
});

it('enforces the model deny-list against the table a write targets', function (): void {
    // `deny_models` holds class names, but the persistence guard — the only layer that can see
    // which model a write touches — reports the *table*. Comparing a table name against class
    // names never matched, so this deny-list read as protection while enforcing nothing.
    config()->set('impersonator.modes.limited.deny_models', [User::class]);
    config()->set('impersonator.modes.limited.deny_routes', []);
    config()->set('impersonator.modes.limited.deny_paths', []);

    impersonateAs($this->admin, $this->target, 'limited');

    // The guard turns on because deny_models is configured, and the write is refused by table.
    $this->get('/app/sneaky-write')->assertForbidden();

    expect(User::find(1)?->name)->not->toBe('changed via GET');
});

it('leaves an undenied model alone in limited mode', function (): void {
    config()->set('impersonator.modes.limited.deny_models', ['App\\Models\\PaymentMethod']);
    config()->set('impersonator.modes.limited.deny_routes', []);
    config()->set('impersonator.modes.limited.deny_paths', []);

    impersonateAs($this->admin, $this->target, 'limited');

    // A class that is not installed cannot resolve to a table, and an unresolvable entry must not
    // deny an unrelated write — guessing there would block whatever happened to share a name.
    $this->get('/app/sneaky-write')->assertOk();
});

// ── the guard must read every driver's identifier quoting ───────────────────

it('exempts a table however the driver qualifies and quotes it', function (string $statement): void {
    // The regression this exists for. The old pattern stopped at the first delimiter, so
    // `"public"."sessions"` parsed as table `public`, never matched the exemption, and read_only
    // blocked Laravel's own session write — refusing every request on PostgreSQL and MySQL. It went
    // unseen because the suite runs SQLite, which emits unqualified names.
    impersonateAs($this->admin, $this->target, 'read_only');

    $guard = app(PersistenceGuard::class);
    $guard->arm(
        Impersonator::current(),
        app(ModeRegistry::class)->enforcer(Mode::of('read_only')),
        'app/orders',
        ['sessions'],
    );

    expect($guard->inspect($statement))->toBeNull();

    $guard->disarm();
})->with([
    'sqlite / bare' => ['update sessions set payload = ?'],
    'sqlite quoted' => ['update "sessions" set "payload" = ?'],
    'postgres qualified' => ['update "public"."sessions" set "payload" = ?'],
    'mysql qualified' => ['update `mydb`.`sessions` set `payload` = ?'],
    'sqlsrv qualified' => ['delete from [dbo].[sessions] where [id] = ?'],
]);

it('accepts an exempt entry written in either form', function (): void {
    // An application may write `public.sessions` in its exempt list rather than `sessions`.
    impersonateAs($this->admin, $this->target, 'read_only');

    $guard = app(PersistenceGuard::class);
    $guard->arm(
        Impersonator::current(),
        app(ModeRegistry::class)->enforcer(Mode::of('read_only')),
        'app/orders',
        ['public.sessions'],
    );

    expect($guard->inspect('update "public"."sessions" set "payload" = ?'))->toBeNull();

    $guard->disarm();
});

it('still denies a qualified write to a table that is not exempt', function (): void {
    // The other half: reading the whole chain must not accidentally exempt everything.
    impersonateAs($this->admin, $this->target, 'read_only');

    $guard = app(PersistenceGuard::class);
    $guard->arm(
        Impersonator::current(),
        app(ModeRegistry::class)->enforcer(Mode::of('read_only')),
        'app/orders',
        ['sessions'],
    );

    $decision = $guard->inspect('update "public"."users" set "name" = ? where "id" = ?');

    expect($decision)->not->toBeNull()
        ->and($decision->denied())->toBeTrue();

    $guard->disarm();
});
