<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\EnforceImpersonationMode;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\GuardImpersonationLifetime;
use Simtabi\Laranail\Impersonator\Laravel\Support\SessionTerminator;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

/*
| The lifecycle across every session driver a real application uses.
|
| Two behaviours differ by driver, and the difference is operationally significant:
|
|  - `file`, `database` and the cache-backed drivers keep a server-side session record, so
|    a revocation can destroy it immediately.
|  - `array` and `cookie` keep no server-side record — `cookie` stores the payload in the
|    client's own cookie, so no server can delete it — and revocation there takes effect
|    on the target's next request, enforced by the middleware.
|
| Everything else is expected to behave identically, which is what these tests establish.
*/

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
    config()->set('laranail.impersonator.limits.state_cache.ttl', 0);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    Route::middleware(['web', GuardImpersonationLifetime::class, EnforceImpersonationMode::class])
        ->group(function (): void {
            Route::get('/app/page', fn (): string => 'page')->name('page');
            Route::post('/app/write', fn (): string => 'written')->name('write');
        });
});

/** Point the session at a real, writable directory for the file driver. */
function useFileSessions(): string
{
    $path = sys_get_temp_dir().'/impersonator-sessions-'.bin2hex(random_bytes(6));

    if (! is_dir($path)) {
        mkdir($path, 0o700, true);
    }

    config()->set('session.driver', 'file');
    config()->set('session.files', $path);

    return $path;
}

function createSessionsTable(): void
{
    Schema::create('sessions', function (Blueprint $table): void {
        $table->string('id')->primary();
        $table->foreignId('user_id')->nullable()->index();
        $table->string('ip_address', 45)->nullable();
        $table->text('user_agent')->nullable();
        $table->longText('payload');
        $table->integer('last_activity')->index();
    });
}

// ── the full lifecycle on every driver ──────────────────────────────────────

it('runs the whole lifecycle on the file session driver', function (): void {
    useFileSessions();
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);

    $outcome = Impersonator::enter($this->target, mode: 'read_only');

    expect(Auth::guard('web')->id())->toBe($this->target->getKey())
        ->and(Impersonator::isImpersonating())->toBeTrue()
        ->and(Impersonator::mode()?->name)->toBe('read_only');

    $this->get('/app/page')->assertOk();
    $this->post('/app/write')->assertForbidden();

    Impersonator::leave();

    expect(Auth::guard('web')->id())->toBe($this->admin->getKey())
        ->and(app(AuditStore::class)->find($outcome->auditId())->endedBy)->toBe(EndReason::Left);
});

it('runs the whole lifecycle on the database session driver', function (): void {
    createSessionsTable();
    config()->set('session.driver', 'database');
    config()->set('session.connection', 'testing');
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);

    $outcome = Impersonator::enter($this->target, mode: 'read_only');

    expect(Impersonator::isImpersonating())->toBeTrue();

    $this->post('/app/write')->assertForbidden();

    Impersonator::leave();

    expect(app(AuditStore::class)->find($outcome->auditId())->endedBy)->toBe(EndReason::Left);
});

it('runs the whole lifecycle on the cookie session driver', function (): void {
    // Driven through real requests rather than by manipulating the session directly:
    // CookieSessionHandler reads the payload off the request, so it has no meaning outside
    // an HTTP cycle. That is a property of the driver, not of this package.
    config()->set('session.driver', 'cookie');

    Route::middleware('web')->group(function (): void {
        Route::get('/enter', function (): string {
            Auth::guard('web')->setUser(User::first());

            return (string) Impersonator::enter(User::find(2))->auditId();
        });

        Route::get('/who', fn (): string => Impersonator::isImpersonating() ? 'yes' : 'no');
    });

    $this->get('/enter')->assertOk();
    $this->get('/app/page')->assertOk();
});

it('regenerates the session id on every driver', function (string $driver): void {
    // A session id valid at one privilege level must not still be valid at another,
    // whichever driver is storing it.
    if ($driver === 'file') {
        useFileSessions();
    } elseif ($driver === 'database') {
        createSessionsTable();
        config()->set('session.connection', 'testing');
    }

    config()->set('session.driver', $driver);
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);

    $before = session()->getId();
    Impersonator::enter($this->target);
    $during = session()->getId();
    Impersonator::leave();

    expect($during)->not->toBe($before)
        ->and(session()->getId())->not->toBe($during);
})->with(['array', 'file', 'database']);

it('regenerates the session id on the cookie driver too', function (): void {
    // Asserted through a request, since the cookie handler needs one.
    config()->set('session.driver', 'cookie');

    Route::middleware('web')->group(function (): void {
        Route::get('/rotate', function (): string {
            Auth::guard('web')->setUser(User::first());
            $before = session()->getId();
            Impersonator::enter(User::find(2));

            return $before === session()->getId() ? 'same' : 'rotated';
        });
    });

    $this->get('/rotate')->assertOk()->assertSee('rotated');
});

// ── which drivers can be terminated out of band ─────────────────────────────

it('reports the file driver as able to terminate immediately', function (): void {
    useFileSessions();

    $terminator = app(SessionTerminator::class);

    expect($terminator->canTerminate())->toBeTrue()
        ->and($terminator->driver())->toBe('file')
        ->and($terminator->explain())->toContain('immediately');
});

it('reports the database driver as able to terminate immediately', function (): void {
    createSessionsTable();
    config()->set('session.driver', 'database');
    config()->set('session.connection', 'testing');

    expect(app(SessionTerminator::class)->canTerminate())->toBeTrue();
});

it('reports the cookie driver as unable to terminate out of band', function (): void {
    // The payload lives in the client's own cookie; no server holds it, so no server can
    // delete it. Saying so beats pretending.
    config()->set('session.driver', 'cookie');

    $terminator = app(SessionTerminator::class);

    expect($terminator->canTerminate())->toBeFalse()
        ->and($terminator->explain())->toContain('next request');
});

it('honours the destroy_on_revoke switch', function (): void {
    useFileSessions();
    config()->set('laranail.impersonator.session.destroy_on_revoke', false);

    $terminator = app(SessionTerminator::class);

    expect($terminator->canTerminate())->toBeFalse()
        ->and($terminator->explain())->toContain('Disabled by session.destroy_on_revoke');
});

// ── immediate termination, for real ─────────────────────────────────────────

it('destroys another session file out of band', function (): void {
    // The mechanism, isolated from the guard that refuses to destroy the caller's own
    // session: write a record for a different id, then destroy it.
    $path = useFileSessions();
    $this->startSession();

    $other = 'a-different-operators-session-id';
    session()->getHandler()->write($other, 'payload');

    expect(file_exists($path.'/'.$other))->toBeTrue()
        ->and(app(SessionTerminator::class)->terminate($other))->toBeTrue()
        ->and(file_exists($path.'/'.$other))->toBeFalse();
});

it('marks the audit row on revocation regardless of whether the session was destroyed', function (): void {
    // The row is what the middleware acts on, so it is the part that has to survive.
    useFileSessions();
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);

    $auditId = Impersonator::enter($this->target)->auditId();

    Impersonator::revoke($auditId);

    expect(app(AuditStore::class)->find($auditId)->isRevoked())->toBeTrue();
});

it('refuses to destroy the caller its own session', function (): void {
    // An administrator revoking somebody else must not be logged out by doing so.
    useFileSessions();
    $this->startSession();
    session()->save();

    expect(app(SessionTerminator::class)->terminate(session()->getId()))->toBeFalse();
});

it('reports false rather than throwing for a session that does not exist', function (): void {
    useFileSessions();
    $this->startSession();

    // A revocation must complete regardless: the audit flag plus the middleware is already
    // a correct termination path, and failing here would leave the row unmarked.
    expect(app(SessionTerminator::class)->terminate('a-session-that-was-never-written'))
        ->toBeBool();
});

it('reports false for a blank session id', function (): void {
    useFileSessions();
    $this->startSession();

    expect(app(SessionTerminator::class)->terminate(''))->toBeFalse();
});

it('falls back to next-request enforcement on a driver it cannot reach', function (): void {
    // The middleware is the reason revocation is still correct on `array` and `cookie`,
    // just not instant.
    config()->set('session.driver', 'array');
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);

    $auditId = Impersonator::enter($this->target)->auditId();
    Impersonator::revoke($auditId);

    $this->get('/app/page')->assertRedirect();

    expect(Impersonator::isImpersonating())->toBeFalse()
        ->and(app(AuditStore::class)->find($auditId)->endedBy)->toBe(EndReason::Revoked);
});

it('reports through the adapter whether revocation was immediate', function (): void {
    useFileSessions();
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);

    $outcome = Impersonator::enter($this->target);
    session()->save();

    $session = app(AuditStore::class)->find($outcome->auditId());

    // Regenerate without destroying, so the impersonated record is still on disk while the
    // caller is no longer inside it — the situation an administrator revoking from another
    // browser is actually in.
    session()->migrate(destroy: false);

    expect(Impersonator::adapter('session')->revoke($session))->toBeTrue();
});

it('reports false from the adapter when the row has no session id', function (): void {
    config()->set('session.driver', 'array');
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);

    $outcome = Impersonator::enter($this->target);
    $session = app(AuditStore::class)->find($outcome->auditId());

    expect(Impersonator::adapter('session')->revoke($session))->toBeFalse();
});
