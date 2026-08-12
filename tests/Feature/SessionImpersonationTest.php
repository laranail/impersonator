<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Login;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Enums\CredentialType;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationEnded;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRejected;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationStarted;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Exceptions\InvalidMode;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Support\SessionState;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\ProtectedUser;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->string('email')->nullable();
        $table->string('password')->nullable();
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    // The concurrency cap ships at 1; these tests are about the lifecycle, and
    // the cap has its own coverage below.
    config()->set('impersonator.limits.max_active_per_impersonator', 5);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    $this->startSession();
});

function enterAs(User $admin, User $target, ...$args)
{
    Auth::guard('web')->setUser($admin);

    return Impersonator::enter($target, ...$args);
}

it('authenticates the target on the configured guard', function (): void {
    enterAs($this->admin, $this->target);

    expect(Auth::guard('web')->id())->toBe($this->target->getKey());
});

it('reports the impersonation as active from server-side state', function (): void {
    enterAs($this->admin, $this->target);

    $session = Impersonator::current();

    expect(Impersonator::isImpersonating())->toBeTrue()
        ->and($session)->not->toBeNull()
        // Compared as strings: the audit columns are strings so one table can hold
        // both int-keyed and UUID-keyed models, which is exactly why Identity::is()
        // compares loosely on the id's PHP type.
        ->and((string) $session->target->id)->toBe((string) $this->target->getKey())
        ->and((string) $session->impersonator->id)->toBe((string) $this->admin->getKey())
        ->and($session->mode->name)->toBe('full')
        ->and($session->driver)->toBe('session')
        ->and($session->adapter)->toBe('session');
});

it('names the impersonator as the actor, not the target', function (): void {
    // The correctness fix: during impersonation auth()->user() is the target, so
    // anything recording a causer from the auth context blames the wrong person.
    enterAs($this->admin, $this->target);

    expect(Auth::guard('web')->id())->toBe($this->target->getKey())
        ->and(Impersonator::actor()?->getKey())->toBe($this->admin->getKey())
        ->and(Impersonator::target()?->getKey())->toBe($this->target->getKey());
});

it('regenerates the session id on enter', function (): void {
    // A session id valid at one privilege level must not still be valid at
    // another, or an id fixated beforehand keeps working afterwards.
    Auth::guard('web')->setUser($this->admin);
    $before = session()->getId();

    Impersonator::enter($this->target);

    expect(session()->getId())->not->toBe($before);
});

it('regenerates the session id on leave as well', function (): void {
    enterAs($this->admin, $this->target);
    $during = session()->getId();

    Impersonator::leave();

    expect(session()->getId())->not->toBe($during);
});

it('does not regenerate when regeneration is switched off', function (): void {
    config()->set('impersonator.session.regenerate', false);
    Auth::guard('web')->setUser($this->admin);
    $before = session()->getId();

    Impersonator::enter($this->target);

    expect(session()->getId())->toBe($before);
});

it('does not fire the application login listeners for a silent login', function (): void {
    // An impersonated login is not the target signing in; treating it as one sends
    // them "new sign-in" mail and corrupts last-login columns.
    Event::fake([Login::class]);

    enterAs($this->admin, $this->target);

    Event::assertNotDispatched(Login::class);
});

it('fires the login event when silent login is switched off', function (): void {
    config()->set('impersonator.session.silent_login', false);
    Event::fake([Login::class]);

    enterAs($this->admin, $this->target);

    Event::assertDispatched(Login::class);
});

it('restores the impersonator on leave when both sides share a guard', function (): void {
    enterAs($this->admin, $this->target);

    Impersonator::leave();

    expect(Auth::guard('web')->id())->toBe($this->admin->getKey())
        ->and(Impersonator::isImpersonating())->toBeFalse();
});

it('clears the session state on leave', function (): void {
    enterAs($this->admin, $this->target);

    Impersonator::leave();

    expect(app(SessionState::class)->has())->toBeFalse()
        ->and(Impersonator::current())->toBeNull();
});

it('returns a session credential that carries no secret', function (): void {
    $outcome = enterAs($this->admin, $this->target);

    expect($outcome->isStarted())->toBeTrue()
        ->and($outcome->credential?->type)->toBe(CredentialType::Session)
        ->and($outcome->credential?->hasSecret())->toBeFalse();
});

it('opens the audit row before authenticating', function (): void {
    // If authentication ran first, a failure would leave an impersonation that
    // happened with no record of it.
    $outcome = enterAs($this->admin, $this->target);

    $row = app(AuditStore::class)->find($outcome->auditId());

    expect($row)->not->toBeNull()
        ->and($row->isActive())->toBeTrue()
        ->and((string) $row->impersonator->id)->toBe((string) $this->admin->getKey())
        ->and((string) $row->target->id)->toBe((string) $this->target->getKey());
});

it('records the session id on the audit row so revocation can find it', function (): void {
    $outcome = enterAs($this->admin, $this->target);

    $row = app(AuditStore::class)->find($outcome->auditId());

    expect($row->sessionId)->toBe(session()->getId())
        ->and($row->credentialHash)->toBe(hash('sha256', session()->getId()));
});

it('closes the audit row on leave with the end reason', function (): void {
    $outcome = enterAs($this->admin, $this->target);

    Impersonator::leave();

    $row = app(AuditStore::class)->find($outcome->auditId());

    expect($row->hasEnded())->toBeTrue()
        ->and($row->endedBy)->toBe(EndReason::Left);
});

it('sets an expiry from max_duration', function (): void {
    config()->set('impersonator.limits.max_duration', 30);

    $outcome = enterAs($this->admin, $this->target);

    expect($outcome->session->expiresAt)->not->toBeNull()
        ->and($outcome->session->expiresAt->getTimestamp())
        ->toBeGreaterThan((new DateTimeImmutable)->getTimestamp());
});

it('leaves the expiry unset when max_duration is null', function (): void {
    config()->set('impersonator.limits.max_duration', null);

    expect(enterAs($this->admin, $this->target)->session->expiresAt)->toBeNull();
});

it('dispatches started and ended events', function (): void {
    Event::fake([ImpersonationStarted::class, ImpersonationEnded::class]);

    enterAs($this->admin, $this->target);
    Event::assertDispatched(ImpersonationStarted::class);

    // The fake swallowed the start event, so the driver's state is still set and
    // leave() proceeds normally.
    Impersonator::leave();
    Event::assertDispatched(
        ImpersonationEnded::class,
        static fn (ImpersonationEnded $e): bool => $e->reason === EndReason::Left,
    );
});

it('returns null from leave when nothing is active', function (): void {
    expect(Impersonator::leave())->toBeNull();
});

// ── Failing paths ───────────────────────────────────────────────────────────

it('refuses self-impersonation', function (): void {
    Auth::guard('web')->setUser($this->admin);

    expect(fn () => Impersonator::enter($this->admin))
        ->toThrow(ImpersonationDenied::class);

    expect(Impersonator::isImpersonating())->toBeFalse();
});

it('refuses nested impersonation', function (): void {
    // Once an impersonated session can reach a third account, the audit trail
    // stops describing who actually acted.
    $third = User::create(['name' => 'Third']);
    enterAs($this->admin, $this->target);

    expect(fn () => Impersonator::enter($third, impersonator: $this->target))
        ->toThrow(ImpersonationDenied::class);
});

it('allows nesting only when explicitly configured', function (): void {
    config()->set('impersonator.authorization.allow_nested', true);
    $third = User::create(['name' => 'Third']);
    enterAs($this->admin, $this->target);

    expect(Impersonator::enter($third, impersonator: $this->target)->isStarted())->toBeTrue();
});

it('refuses a soft-deleted target', function (): void {
    $this->target->delete();
    Auth::guard('web')->setUser($this->admin);

    expect(fn () => Impersonator::enter($this->target))
        ->toThrow(ImpersonationDenied::class);
});

it('refuses a target class that is not allowlisted', function (): void {
    config()->set('impersonator.targets.allowlist', []);
    Auth::guard('web')->setUser($this->admin);

    expect(fn () => Impersonator::enter($this->target))
        ->toThrow(ImpersonationDenied::class);
});

it('refuses a missing reason when one is required', function (): void {
    config()->set('impersonator.reason.require', true);
    Auth::guard('web')->setUser($this->admin);

    expect(fn () => Impersonator::enter($this->target))
        ->toThrow(ImpersonationDenied::class);

    expect(Impersonator::enter($this->target, reason: 'Ticket #4182')->isStarted())->toBeTrue();
});

it('refuses a reason that exceeds the configured bound', function (): void {
    config()->set('impersonator.reason.require', true);
    config()->set('impersonator.reason.max_length', 10);
    Auth::guard('web')->setUser($this->admin);

    expect(fn () => Impersonator::enter($this->target, reason: str_repeat('x', 11)))
        ->toThrow(ImpersonationDenied::class);
});

it('refuses when impersonation is disabled entirely', function (): void {
    config()->set('impersonator.enabled', false);
    Auth::guard('web')->setUser($this->admin);

    expect(fn () => Impersonator::enter($this->target))
        ->toThrow(ImpersonationDenied::class);
});

it('refuses an unregistered mode', function (): void {
    // Strict resolution: a typo must never fall back to something permissive.
    Auth::guard('web')->setUser($this->admin);

    expect(fn () => Impersonator::enter($this->target, mode: 'ful'))
        ->toThrow(InvalidMode::class);
});

it('accepts each built-in mode', function (string $mode): void {
    Auth::guard('web')->setUser($this->admin);

    expect(Impersonator::enter($this->target, mode: $mode)->session->mode->name)->toBe($mode);
})->with(['read_only', 'limited', 'full']);

it('enforces the concurrency cap', function (): void {
    config()->set('impersonator.limits.max_active_per_impersonator', 1);
    $third = User::create(['name' => 'Third']);
    config()->set('impersonator.authorization.allow_nested', true);

    enterAs($this->admin, $this->target);

    expect(fn () => Impersonator::enter($third, impersonator: $this->admin))
        ->toThrow(ImpersonationDenied::class);
});

it('refuses a target somebody else is already impersonating', function (): void {
    config()->set('impersonator.limits.deny_when_target_busy', true);
    config()->set('impersonator.authorization.allow_nested', true);
    $other = User::create(['name' => 'Other admin']);

    enterAs($this->admin, $this->target);

    expect(fn () => Impersonator::enter($this->target, impersonator: $other))
        ->toThrow(ImpersonationDenied::class);
});

it('honours the canBeImpersonated model opt-out', function (): void {
    config()->set('impersonator.targets.allowlist', [
        'user' => User::class,
        'protected' => ProtectedUser::class,
    ]);
    $protected = ProtectedUser::create(['name' => 'Founder']);
    Auth::guard('web')->setUser($this->admin);

    expect(fn () => Impersonator::enter($protected))->toThrow(ImpersonationDenied::class);
});

it('honours the canImpersonate model hook on the impersonator', function (): void {
    config()->set('impersonator.targets.allowlist', [
        'user' => User::class,
        'protected' => ProtectedUser::class,
    ]);
    $restricted = ProtectedUser::create(['name' => 'Restricted']);

    expect(fn () => Impersonator::enter($this->target, impersonator: $restricted))
        ->toThrow(ImpersonationDenied::class);
});

it('treats an absent model hook as no opinion rather than a refusal', function (): void {
    // Requiring every model to implement both hooks would make the trait
    // mandatory; they are an override, not a gate everyone must pass.
    expect(method_exists($this->target, 'canBeImpersonated'))->toBeFalse()
        ->and(enterAs($this->admin, $this->target)->isStarted())->toBeTrue();
});

it('dispatches a rejection event carrying the decision code', function (): void {
    // A rejection nobody can subscribe to is a rejection nobody alerts on.
    Event::fake([ImpersonationRejected::class]);
    Auth::guard('web')->setUser($this->admin);

    try {
        Impersonator::enter($this->admin);
    } catch (ImpersonationDenied) {
        // expected
    }

    Event::assertDispatched(
        ImpersonationRejected::class,
        static fn (ImpersonationRejected $e): bool => $e->decision->code === Decision::SELF_IMPERSONATION,
    );
});

it('reports whether a target could be impersonated without doing it', function (): void {
    Auth::guard('web')->setUser($this->admin);

    expect(Impersonator::canImpersonate($this->target)->allowed)->toBeTrue()
        ->and(Impersonator::canImpersonate($this->admin)->code)->toBe(Decision::SELF_IMPERSONATION)
        ->and(Impersonator::isImpersonating())->toBeFalse();
});
