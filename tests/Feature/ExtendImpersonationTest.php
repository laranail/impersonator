<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationExtended;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\GuardImpersonationLifetime;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

/*
| Timed impersonation, end to end.
|
| The default window is short so that exposure is bounded; extension is what keeps a short
| default usable. Both halves need holding to: a window nobody can extend gets configured away,
| and an extension nobody bounds is not a window.
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

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

it('defaults to a ten minute window', function (): void {
    // The published default. Asserted because it is a security posture, not a preference — a
    // silent bump back to an hour is exactly the regression worth catching.
    expect(config('laranail.impersonator.limits.max_duration'))->toBe(10);

    Impersonator::enter($this->target);

    $session = Impersonator::current();

    expect($session?->remainingSeconds(now()->toDateTimeImmutable()))
        ->toBeGreaterThan(9 * 60)
        ->toBeLessThanOrEqual(10 * 60);
});

it('moves the deadline on both the audit row and the session copy', function (): void {
    // Both, and that is the point. The lifetime middleware terminates on whichever it sees
    // expired first, so a durable row extended while the session copy stays stale would end
    // the impersonation the operator just extended.
    Impersonator::enter($this->target);

    $before = Impersonator::current();
    $outcome = Impersonator::extendSession();

    $row = ImpersonationAudit::query()->find($before?->auditId);

    expect($outcome->granted())->toBeTrue()
        ->and($outcome->grant->seconds())->toBe(600)
        ->and($row?->getAttribute('extensions'))->toBe(1)
        ->and($row?->getAttribute('extended_at'))->not->toBeNull()
        ->and(Impersonator::current()?->expiresAt?->getTimestamp())
        ->toBe($outcome->grant->expiresAt?->getTimestamp())
        ->and(Impersonator::current()?->extensions)->toBe(1);
});

it('survives past the original deadline once extended', function (): void {
    // The behavioural claim. Without the extension this request terminates; with it the
    // operator keeps working.
    Route::middleware(['web', GuardImpersonationLifetime::class])
        ->get('/app/inside', fn (): string => 'ok');

    Impersonator::enter($this->target);
    Impersonator::extendSession();

    $this->travel(11)->minutes();

    $this->get('/app/inside')->assertOk();
    expect(Impersonator::isImpersonating())->toBeTrue();

    // And still terminates at the new deadline rather than running forever.
    $this->travel(11)->minutes();

    $this->get('/app/inside')->assertRedirect();
    expect(Impersonator::isImpersonating())->toBeFalse();
});

it('stops at the ceiling however many extensions are allowed', function (): void {
    config()->set('laranail.impersonator.limits.extension.max', null);
    config()->set('laranail.impersonator.limits.extension.max_total_duration', 25);

    Impersonator::enter($this->target);

    // 10 -> 20, then clamped 20 -> 25, then refused.
    expect(Impersonator::extendSession()->grant->seconds())->toBe(600)
        ->and(Impersonator::extendSession()->grant->seconds())->toBe(300);

    $third = Impersonator::extendSession();

    expect($third->denied())->toBeTrue()
        ->and($third->grant->decision->code)->toBe(Decision::EXTENSION_CEILING)
        // The value objects are plain DateTimeImmutable, not Carbon, so the arithmetic is
        // done here rather than with a Carbon helper that does not exist on them.
        ->and(($session = Impersonator::current()) === null ? null : intdiv(
            $session->expiresAt->getTimestamp() - $session->startedAt->getTimestamp(),
            60,
        ))->toBe(25);
});

it('spends the allowance exactly once per extension', function (): void {
    config()->set('laranail.impersonator.limits.extension.max', 2);
    config()->set('laranail.impersonator.limits.extension.max_total_duration', null);

    Impersonator::enter($this->target);

    expect(Impersonator::extendSession()->granted())->toBeTrue()
        ->and(Impersonator::extendSession()->granted())->toBeTrue();

    $third = Impersonator::extendSession();

    expect($third->grant->decision->code)->toBe(Decision::EXTENSION_LIMIT)
        ->and(Impersonator::current()?->extensions)->toBe(2);
});

it('refuses when nobody is impersonating', function (): void {
    $outcome = Impersonator::extendSession();

    expect($outcome->denied())->toBeTrue()
        ->and($outcome->session)->toBeNull()
        ->and($outcome->grant->decision->code)->toBe(Decision::NOT_IMPERSONATING);
});

it('refuses to outrun a revocation', function (): void {
    // The dangerous case: an administrator has pulled the switch but the session has not yet
    // made the request that closes it. Buying time inside that gap must not work.
    Impersonator::enter($this->target);

    $auditId = (string) Impersonator::current()?->auditId;
    app(AuditStore::class)->markRevoked($auditId);

    $outcome = Impersonator::extendSession();

    expect($outcome->denied())->toBeTrue()
        ->and($outcome->grant->decision->code)->toBe(Decision::SESSION_TERMINATED);
});

it('refuses when extension is switched off', function (): void {
    config()->set('laranail.impersonator.limits.extension.enabled', false);

    Impersonator::enter($this->target);

    expect(Impersonator::extendSession()->grant->decision->code)->toBe(Decision::EXTENSION_DISABLED)
        ->and(Impersonator::canExtendSession()->denied())->toBeTrue();
});

it('dispatches an event carrying the new deadline and the count', function (): void {
    Event::fake([ImpersonationExtended::class]);

    Impersonator::enter($this->target);
    Impersonator::extendSession();

    Event::assertDispatched(
        ImpersonationExtended::class,
        fn (ImpersonationExtended $event): bool => $event->session->extensions === 1
            && $event->grant->seconds() === 600
            && $event->session->expiresAt?->getTimestamp() === $event->grant->expiresAt?->getTimestamp(),
    );
});

it('extends over HTTP and refuses with the decision code', function (): void {
    config()->set('laranail.impersonator.limits.extension.max', 1);

    Impersonator::enter($this->target);

    $this->postJson(route('impersonator.extend'))
        ->assertOk()
        ->assertJson(['granted' => true, 'seconds' => 600, 'extensions' => 1]);

    $this->postJson(route('impersonator.extend'))
        ->assertStatus(403)
        ->assertJson(['reason' => Decision::EXTENSION_LIMIT]);
});

it('is reachable from a read-only impersonation', function (): void {
    // Same reasoning as leaving. A mode that lets an operator's window run out with no way to
    // keep it is a mode that pushes them to leave and re-enter, which mints a second audit row
    // for one piece of work.
    Impersonator::enter($this->target, 'read_only');

    $this->postJson(route('impersonator.extend'))->assertOk();

    expect(Impersonator::current()?->extensions)->toBe(1);
});

it('reports whether the button should render without spending anything', function (): void {
    Impersonator::enter($this->target);

    expect(Impersonator::canExtendSession()->granted())->toBeTrue()
        // Read-only: asking must not consume an extension.
        ->and(Impersonator::current()?->extensions)->toBe(0);
});

it('holds the window shut until the final minutes when configured', function (): void {
    config()->set('laranail.impersonator.limits.extension.within', 3);

    Impersonator::enter($this->target);

    expect(Impersonator::extendSession()->grant->decision->code)->toBe(Decision::EXTENSION_TOO_EARLY);

    $this->travel(8)->minutes();

    expect(Impersonator::extendSession()->granted())->toBeTrue();
});

it('leaves the audit hash chain verifiable after an extension', function (): void {
    // The property that makes an extendable window acceptable in an audited system: the expiry
    // is not among the chained facts, so moving it cannot forge or break tamper evidence.
    config()->set('laranail.impersonator.audit.tamper_evidence', true);
    config()->set('laranail.impersonator.audit.hash_key', str_repeat('k', 64));

    Impersonator::enter($this->target);

    $store = app(AuditStore::class);
    $row = ImpersonationAudit::query()->find((string) Impersonator::current()?->auditId);
    $before = $row?->getAttribute('hash');

    Impersonator::extendSession();

    $row = ImpersonationAudit::query()->find((string) Impersonator::current()?->auditId);

    expect($row?->getAttribute('hash'))->toBe($before)
        ->and($store->chainFactsFromRow($row))->not->toHaveKey('expires_at');
});
