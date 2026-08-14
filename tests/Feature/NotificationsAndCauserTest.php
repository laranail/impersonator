<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\FailureReporter;
use Simtabi\Laranail\Impersonator\Core\Events\TargetNotified;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Notifications\ImpersonationSecurityAlert;
use Simtabi\Laranail\Impersonator\Laravel\Notifications\TargetAccountAccessed;
use Simtabi\Laranail\Impersonator\Laravel\Support\CauserResolver;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\PlainUser;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->string('email')->nullable();
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 5);
    config()->set('laranail.impersonator.limits.state_cache.ttl', 0);

    $this->admin = User::create(['name' => 'Admin', 'email' => 'admin@example.com']);
    $this->target = User::create(['name' => 'Customer', 'email' => 'customer@example.com']);

    $this->startSession();
});

function enterNow(User $admin, User $target, string $mode = 'full'): string
{
    Auth::guard('web')->setUser($admin);

    return Impersonator::enter($target, mode: $mode)->auditId();
}

// ── target disclosure ───────────────────────────────────────────────────────

it('sends nothing by default', function (): void {
    // Enabling either notification changes what users receive, so both are opt-in.
    Notification::fake();

    enterNow($this->admin, $this->target);

    Notification::assertNothingSent();
});

it('tells the target their account was accessed when enabled', function (): void {
    config()->set('laranail.impersonator.notifications.notify_target', true);
    Notification::fake();

    enterNow($this->admin, $this->target);

    Notification::assertSentTo($this->target, TargetAccountAccessed::class);
});

it('does not name the operator to the target', function (): void {
    // Naming them would hand every customer the identity of individual staff; the audit
    // trail already records it for anyone with a legitimate reason to ask.
    config()->set('laranail.impersonator.notifications.notify_target', true);
    $auditId = enterNow($this->admin, $this->target);

    $session = app(AuditStore::class)->find($auditId);
    $payload = new TargetAccountAccessed($session)->toArray($this->target);
    $mail = new TargetAccountAccessed($session)->toMail($this->target);

    $rendered = json_encode($payload) . json_encode($mail->introLines);

    expect($rendered)->not->toContain('Admin')
        ->and($rendered)->not->toContain('admin@example.com')
        ->and($payload['impersonation_audit_id'])->toBe($auditId);
});

it('explains each mode in plain language rather than by name', function (string $mode, string $expected): void {
    $auditId = enterNow($this->admin, $this->target, $mode);
    $session = app(AuditStore::class)->find($auditId);

    $lines = implode(' ', new TargetAccountAccessed($session)->toMail($this->target)->introLines);

    expect($lines)->toContain($expected);
})->with([
    ['read_only', 'could not change anything'],
    ['limited', 'could not change your password'],
    ['full', 'same access to your account that you do'],
]);

it('emits an event once the target has been told', function (): void {
    // So a compliance report can evidence that disclosure happened, not only that it was
    // configured.
    config()->set('laranail.impersonator.notifications.notify_target', true);
    Notification::fake();
    Event::fake([TargetNotified::class]);

    enterNow($this->admin, $this->target);

    Event::assertDispatched(TargetNotified::class);
});

// ── security alerts ─────────────────────────────────────────────────────────

it('alerts the security channel on a full-mode entry', function (): void {
    config()->set('laranail.impersonator.notifications.security_channel.enabled', true);
    config()->set('laranail.impersonator.notifications.security_channel.mail', ['security@example.com']);
    Notification::fake();

    enterNow($this->admin, $this->target, 'full');

    Notification::assertSentOnDemand(ImpersonationSecurityAlert::class);
});

it('does not alert on routine read-only support work', function (): void {
    // An alert channel that fires on everything is one nobody reads.
    config()->set('laranail.impersonator.notifications.security_channel.enabled', true);
    config()->set('laranail.impersonator.notifications.security_channel.mail', ['security@example.com']);
    Notification::fake();

    enterNow($this->admin, $this->target, 'read_only');

    Notification::assertNothingSent();
});

it('alerts on every revocation regardless of mode', function (): void {
    config()->set('laranail.impersonator.notifications.security_channel.enabled', true);
    config()->set('laranail.impersonator.notifications.security_channel.mail', ['security@example.com']);
    $auditId = enterNow($this->admin, $this->target, 'read_only');

    Notification::fake();
    Impersonator::revoke($auditId);

    Notification::assertSentOnDemand(ImpersonationSecurityAlert::class);
});

it('honours the configured trigger list', function (): void {
    config()->set('laranail.impersonator.notifications.security_channel.enabled', true);
    config()->set('laranail.impersonator.notifications.security_channel.mail', ['security@example.com']);
    config()->set('laranail.impersonator.notifications.security_channel.on', ['revoked']);
    Notification::fake();

    enterNow($this->admin, $this->target, 'full');

    Notification::assertNothingSent();
});

it('names the operator in a security alert, unlike the target notice', function (): void {
    // The audience is a security team, and an alert that omits who did it is not
    // actionable.
    $auditId = enterNow($this->admin, $this->target, 'full');
    $session = app(AuditStore::class)->find($auditId);

    $lines = implode(' ', new ImpersonationSecurityAlert($session, 'full_mode_enter')
        ->toMail(new AnonymousNotifiable)->introLines);

    expect($lines)->toContain($auditId)
        ->and($lines)->toContain('full');
});

it('keeps the credential hash and session id out of an alert payload', function (): void {
    // Alerts are forwarded, pasted into chat and archived in places the audit table is
    // not.
    $auditId = enterNow($this->admin, $this->target, 'full');
    $session = app(AuditStore::class)->find($auditId);

    $payload = json_encode(
        new ImpersonationSecurityAlert($session, 'full_mode_enter')
            ->toArray(new AnonymousNotifiable),
    );

    expect($payload)->not->toContain((string) $session->credentialHash)
        ->and($payload)->not->toContain((string) $session->sessionId);
});

it('does not let a failing notification break the impersonation', function (): void {
    // A mail server being down must not stop a support engineer helping a customer.
    config()->set('laranail.impersonator.notifications.notify_target', true);
    config()->set('mail.default', 'nonexistent-transport');

    expect(enterNow($this->admin, $this->target))->toBeString()
        ->and(Impersonator::isImpersonating())->toBeTrue();
});

// ── causer attribution ──────────────────────────────────────────────────────

it('names the impersonator as the causer by default', function (): void {
    // During impersonation auth()->user() is the target, so anything resolving a causer
    // from the auth context records the customer as having done the operator's work.
    enterNow($this->admin, $this->target);

    expect(app(CauserResolver::class)->causer()?->getKey())->toBe($this->admin->getKey());
});

it('names the target under the target strategy', function (): void {
    config()->set('laranail.impersonator.causer.strategy', 'target');
    enterNow($this->admin, $this->target);

    expect(app(CauserResolver::class)->causer()?->getKey())->toBe($this->target->getKey());
});

it('records both under the both strategy', function (): void {
    config()->set('laranail.impersonator.causer.strategy', 'both');
    enterNow($this->admin, $this->target);

    $resolver = app(CauserResolver::class);

    expect($resolver->causer()?->getKey())->toBe($this->admin->getKey())
        ->and($resolver->properties())->toHaveKey('impersonated_target')
        ->and($resolver->properties()['impersonated_by']['id'])->toBe((string) $this->admin->getKey());
});

it('always carries the audit id in the properties', function (): void {
    // A log entry naming the operator but not which impersonation is far harder to
    // reconcile against the trail.
    $auditId = enterNow($this->admin, $this->target);

    expect(app(CauserResolver::class)->properties()['impersonation_audit_id'])->toBe($auditId);
});

it('falls back to the authenticated user outside an impersonation', function (): void {
    Auth::guard('web')->setUser($this->admin);

    $resolver = app(CauserResolver::class);

    expect($resolver->causer()?->getKey())->toBe($this->admin->getKey())
        ->and($resolver->properties())->toBe([])
        ->and($resolver->isImpersonating())->toBeFalse();
});

it('falls back to the default strategy for an unrecognised config value', function (): void {
    // This runs inside somebody else's logging pipeline; a typo must not take down every
    // write in the application.
    config()->set('laranail.impersonator.causer.strategy', 'nonsense');
    enterNow($this->admin, $this->target);

    expect(app(CauserResolver::class)->strategy())->toBe('impersonator')
        ->and(app(CauserResolver::class)->causer()?->getKey())->toBe($this->admin->getKey());
});

it('warns rather than failing when the target cannot be notified', function (): void {
    // A user model without Notifiable is a configuration gap worth surfacing, not a
    // reason to fail the impersonation.
    config()->set('laranail.impersonator.notifications.notify_target', true);
    config()->set('laranail.impersonator.targets.allowlist', ['plain' => PlainUser::class]);

    $warnings = [];
    app()->instance(FailureReporter::class,
        new class($warnings) implements FailureReporter
        {
            public function __construct(public array &$seen) {}

            public function report(Throwable $failure): void
            {
                $this->seen[] = 'report';
            }

            public function warn(string $message, array $context = []): void
            {
                $this->seen[] = $context['actual'] ?? $message;
            }
        });

    $plain = PlainUser::create(['name' => 'Plain']);
    Auth::guard('web')->setUser($this->admin);

    expect(Impersonator::enter($plain)->isStarted())->toBeTrue()
        ->and($warnings)->toContain('model is not notifiable');
});
