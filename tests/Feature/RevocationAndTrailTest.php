<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\TrailStore;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRevoked;
use Simtabi\Laranail\Impersonator\Laravel\Audit\ConcurrencyLimitReached;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\EnforceImpersonationMode;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\GuardImpersonationLifetime;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\RecordImpersonationTrail;
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
    // The state cache would otherwise mask a revocation recorded mid-test.
    config()->set('laranail.impersonator.limits.state_cache.ttl', 0);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    Route::middleware([
        'web',
        GuardImpersonationLifetime::class,
        EnforceImpersonationMode::class,
        RecordImpersonationTrail::class,
    ])->group(function (): void {
        Route::get('/app/dash', fn (): string => 'dash')->name('dash');
        Route::post('/app/save', fn (): string => 'saved')->name('save');
        Route::get('/app/api', fn () => response()->json(['ok' => true]))->name('api');
    });

    $this->startSession();
});

function startImpersonation(User $admin, User $target, string $mode = 'full'): string
{
    Auth::guard('web')->setUser($admin);

    return Impersonator::enter($target, mode: $mode)->auditId();
}

// ── revocation ──────────────────────────────────────────────────────────────

it('records a revocation without ending the row immediately', function (): void {
    // A session can only be terminated from inside itself, so revocation marks the
    // row and the target's next request is what closes it.
    $auditId = startImpersonation($this->admin, $this->target);

    Impersonator::revoke($auditId);

    $row = app(AuditStore::class)->find($auditId);

    expect($row->isRevoked())->toBeTrue()
        ->and($row->isActive())->toBeTrue();
});

it('terminates the session on its next request', function (): void {
    $auditId = startImpersonation($this->admin, $this->target);
    Impersonator::revoke($auditId);

    $this->get('/app/dash')->assertRedirect();

    expect(Impersonator::isImpersonating())->toBeFalse()
        ->and(app(AuditStore::class)->find($auditId)->endedBy)->toBe(EndReason::Revoked);
});

it('does not serve the request it terminates', function (): void {
    // Continuing would serve one more request as the target after access was
    // withdrawn, which is exactly what a kill switch exists to prevent.
    $auditId = startImpersonation($this->admin, $this->target);
    Impersonator::revoke($auditId);

    expect($this->get('/app/dash')->getContent())->not->toContain('dash');
});

it('answers a JSON request with a 403 rather than a redirect', function (): void {
    $auditId = startImpersonation($this->admin, $this->target);
    Impersonator::revoke($auditId);

    $this->getJson('/app/api')->assertForbidden()->assertJsonPath('ended_by', 'revoked');
});

it('emits a revoked event carrying who did it', function (): void {
    Event::fake([ImpersonationRevoked::class]);
    $auditId = startImpersonation($this->admin, $this->target);

    Impersonator::revoke($auditId, note: 'Support escalation');

    Event::assertDispatched(
        ImpersonationRevoked::class,
        static fn (ImpersonationRevoked $e): bool => $e->note === 'Support escalation',
    );
});

it('keeps the original end reason when a leave follows a revocation', function (): void {
    // A `left` overwriting a `revoked` would erase the fact that an administrator
    // intervened.
    $auditId = startImpersonation($this->admin, $this->target);
    Impersonator::revoke($auditId);
    $this->get('/app/dash');

    Impersonator::leave();

    expect(app(AuditStore::class)->find($auditId)->endedBy)->toBe(EndReason::Revoked);
});

it('is idempotent', function (): void {
    $auditId = startImpersonation($this->admin, $this->target);

    Impersonator::revoke($auditId);
    $first = app(AuditStore::class)->find($auditId)->revokedAt;
    Impersonator::revoke($auditId);

    expect(app(AuditStore::class)->find($auditId)->revokedAt?->getTimestamp())
        ->toBe($first?->getTimestamp());
});

// ── max_duration ────────────────────────────────────────────────────────────

it('force-ends an impersonation that outlived max_duration', function (): void {
    config()->set('laranail.impersonator.limits.max_duration', 30);
    $auditId = startImpersonation($this->admin, $this->target);

    $this->travel(31)->minutes();

    $this->get('/app/dash')->assertRedirect();

    expect(Impersonator::isImpersonating())->toBeFalse()
        ->and(app(AuditStore::class)->find($auditId)->endedBy)->toBe(EndReason::Expired);
});

it('leaves an impersonation inside its window alone', function (): void {
    config()->set('laranail.impersonator.limits.max_duration', 30);
    startImpersonation($this->admin, $this->target);

    $this->travel(29)->minutes();

    $this->get('/app/dash')->assertOk();
    expect(Impersonator::isImpersonating())->toBeTrue();
});

// ── action trail ────────────────────────────────────────────────────────────

it('records one trail row per impersonated request', function (): void {
    $auditId = startImpersonation($this->admin, $this->target);

    $this->get('/app/dash');
    $this->post('/app/save');

    $trail = app(TrailStore::class)->forAudit($auditId);

    expect($trail)->toHaveCount(2)
        ->and($trail[0]->method)->toBe('GET')
        ->and($trail[0]->path)->toBe('/app/dash')
        ->and($trail[0]->routeName)->toBe('dash')
        ->and($trail[0]->status)->toBe(200)
        ->and($trail[1]->method)->toBe('POST')
        ->and($trail[1]->isWrite())->toBeTrue();
});

it('records nothing when not impersonating', function (): void {
    Auth::guard('web')->setUser($this->admin);

    $this->get('/app/dash');

    expect(app(TrailStore::class)->countForAudit('nonexistent'))->toBe(0);
});

it('omits payloads by default', function (): void {
    // A request body is the likeliest place for personal data to end up recorded.
    $auditId = startImpersonation($this->admin, $this->target);

    $this->post('/app/save', ['note' => 'hello']);

    expect(app(TrailStore::class)->forAudit($auditId)[0]->payload)->toBeNull();
});

it('redacts a recorded payload', function (): void {
    config()->set('laranail.impersonator.trail.record_payloads', true);
    $auditId = startImpersonation($this->admin, $this->target);

    $this->post('/app/save', [
        'email' => 'ada@example.com',
        'password' => 'hunter2',
        'nested' => ['api_token' => 'abc'],
    ]);

    $payload = app(TrailStore::class)->forAudit($auditId)[0]->payload;

    expect($payload['email'])->toBe('ada@example.com')
        ->and($payload['password'])->toBe('[redacted]')
        ->and($payload['nested']['api_token'])->toBe('[redacted]')
        ->and(json_encode($payload))->not->toContain('hunter2');
});

it('skips ignored paths at any sample rate', function (): void {
    config()->set('laranail.impersonator.trail.ignore_paths', ['app/dash']);
    $auditId = startImpersonation($this->admin, $this->target);

    $this->get('/app/dash');

    expect(app(TrailStore::class)->countForAudit($auditId))->toBe(0);
});

it('records nothing when the trail is disabled', function (): void {
    config()->set('laranail.impersonator.trail.enabled', false);
    $auditId = startImpersonation($this->admin, $this->target);

    $this->get('/app/dash');

    expect(app(TrailStore::class)->countForAudit($auditId))->toBe(0);
});

it('drops every event at a zero sample rate', function (): void {
    config()->set('laranail.impersonator.trail.sample_rate', 0.0);
    $auditId = startImpersonation($this->admin, $this->target);

    $this->get('/app/dash');

    expect(app(TrailStore::class)->countForAudit($auditId))->toBe(0);
});

it('purges the trail with its parent', function (): void {
    $auditId = startImpersonation($this->admin, $this->target);
    $this->get('/app/dash');

    expect(app(TrailStore::class)->countForAudit($auditId))->toBe(1);

    app(TrailStore::class)->purgeForAudit($auditId);

    expect(app(TrailStore::class)->countForAudit($auditId))->toBe(0);
});

// ── concurrency, enforced in the store ──────────────────────────────────────

it('enforces the concurrency cap inside the store, not just the policy', function (): void {
    // The authoritative check: a count read in the policy and an insert performed
    // afterwards is a race two simultaneous requests can both win.
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 1);
    $third = User::create(['name' => 'Third']);

    $request = Impersonator::buildRequest(target: $third, impersonator: $this->admin);
    startImpersonation($this->admin, $this->target);

    expect(fn () => app(AuditStore::class)->open($request))
        ->toThrow(ConcurrencyLimitReached::class);
});
