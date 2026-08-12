<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\PendingCommand;
use Simtabi\Laranail\Impersonator\Core\Support\FailureReport;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
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
});

function doctor(): PendingCommand
{
    return test()->artisan('laranail::impersonator.doctor');
}

/**
 * The command's raw output and exit code, from one unmocked run.
 *
 * Needed wherever a test asserts on more than one phrase, because the mocked console matches at
 * most one `expectsOutputToContain` per output line — and every diagnostic here prints its whole
 * detail on a single line. Returns both, since `withoutMockingConsoleOutput()` stays in effect for
 * the rest of the test and a later `artisan()` would no longer give back a PendingCommand.
 *
 * @return array{output: string, exit: int}
 */
function doctorRun(): array
{
    $exit = test()->withoutMockingConsoleOutput()->artisan('laranail::impersonator.doctor');

    return ['output' => Artisan::output(), 'exit' => (int) $exit];
}

// ── the happy path ──────────────────────────────────────────────────────────

it('passes on a sane configuration', function (): void {
    // Warnings are expected — an unlimited duration and tamper evidence off are both legitimate
    // defaults — but nothing should fail.
    doctor()->assertSuccessful();
});

it('reports the resolved driver and adapter', function (): void {
    doctor()
        ->expectsOutputToContain('[session] resolves.')
        ->assertSuccessful();
});

// ── failures ────────────────────────────────────────────────────────────────

it('fails when the target allowlist is empty', function (): void {
    // Not a permissive default: an empty allowlist refuses every enter, with a message about the
    // target type that reads like a bug in the caller.
    config()->set('impersonator.targets.allowlist', []);

    doctor()
        ->expectsOutputToContain('allowlist is empty')
        ->assertFailed();
});

it('fails when an allowlisted class is not an installed model', function (): void {
    // The registry drops such an entry silently, so the doctor has to compare the raw config
    // against what resolved — iterating the registry would never see the broken entry, because
    // the broken entry is exactly the one that is missing.
    config()->set('impersonator.targets.allowlist', ['ghost' => 'App\\Models\\Ghost']);

    $run = doctorRun();

    expect($run['output'])->toContain('Dropped from the allowlist')
        ->and($run['output'])->toContain('ghost => App\\Models\\Ghost')
        ->and($run['exit'])->toBe(1);
});

it('fails when a configured guard is not defined', function (): void {
    config()->set('impersonator.guards.target', 'nonexistent');

    doctor()
        ->expectsOutputToContain('not defined in config/auth.php')
        ->assertFailed();
});

it('fails when the tables are missing', function (): void {
    config()->set('impersonator.audit.table', 'impersonator_audits_gone');

    $run = doctorRun();

    expect($run['output'])->toContain('Missing: impersonator_audits_gone')
        // The remedy, not just the diagnosis.
        ->and($run['output'])->toContain('vendor:publish')
        ->and($run['exit'])->toBe(1);
});

it('fails when a boot operation degraded', function (): void {
    // The most valuable check: a degradable boot failure leaves an application that starts
    // cleanly and quietly lacks a feature.
    app(FailureReport::class)->recordDegraded(
        'impersonator.boot.routes',
        new RuntimeException('router unavailable'),
    );

    doctor()
        ->expectsOutputToContain('impersonator.boot.routes degraded')
        ->assertFailed();
});

it('fails when the api is exposed without an auth guard', function (): void {
    config()->set('impersonator.api.enabled', true);
    config()->set('impersonator.api.middleware', ['api']);

    doctor()
        ->expectsOutputToContain('unauthenticated remote-control surface')
        ->assertFailed();
});

it('passes when the api is behind an auth guard', function (): void {
    config()->set('impersonator.api.enabled', true);
    config()->set('impersonator.api.middleware', ['api', 'auth:sanctum']);

    doctor()->assertSuccessful();
});

it('fails when tamper evidence is on without a key', function (): void {
    // An application in this state boots cleanly and throws on its first impersonation, so the
    // doctor is the only thing that will say so before a user does. It reports rather than crashes
    // because the check runs before anything resolves the audit store — which is what throws.
    config()->set('impersonator.audit.tamper_evident', true);
    config()->set('impersonator.audit.hash_key', null);

    doctor()
        ->expectsOutputToContain('hash_key is unset')
        ->assertFailed();
});

// ── warnings that must not fail the command ─────────────────────────────────

it('warns but does not fail on an unlimited duration', function (): void {
    config()->set('impersonator.limits.max_duration', null);

    doctor()
        ->expectsOutputToContain('unlimited')
        ->assertSuccessful();
});

it('warns about a short hash key without failing', function (): void {
    config()->set('impersonator.audit.tamper_evident', true);
    config()->set('impersonator.audit.hash_key', 'too-short');

    doctor()
        ->expectsOutputToContain('Use at least 32')
        ->assertSuccessful();
});

it('warns when the master switch is off', function (): void {
    // Off is a deliberate incident posture, not a fault — and revocation still works.
    config()->set('impersonator.enabled', false);

    doctor()
        ->expectsOutputToContain('every enter is refused')
        ->assertSuccessful();
});

it('warns when the token driver has no base domain', function (): void {
    config()->set('impersonator.driver', 'token');
    config()->set('impersonator.urls.base_domain', null);

    doctor()
        ->expectsOutputToContain('base_domain is unset')
        ->assertSuccessful();
});

it('warns when a configured gate ability is not defined', function (): void {
    config()->set('impersonator.authorization.gate_ability', 'impersonate-somehow');

    doctor()
        ->expectsOutputToContain('no such ability is defined')
        ->assertSuccessful();
});

it('reports a defined gate ability as enforced', function (): void {
    Gate::define('impersonate', fn (): bool => true);

    doctor()
        ->expectsOutputToContain('will be consulted')
        ->assertSuccessful();
});

it('warns that a cookie session cannot be killed out of band', function (): void {
    config()->set('session.driver', 'cookie');

    doctor()
        ->expectsOutputToContain('cannot be enforced out of band')
        ->assertSuccessful();
});

it('names the enter-plus-mode permission trap when the rbac policy is active', function (): void {
    // The single most common way an install is quietly broken: an operator holding only the enter
    // permission can impersonate nothing, and the error they get names the mode.
    config()->set('impersonator.authorization.policy', RbacPolicy::class);

    $run = doctorRun();

    expect($run['output'])->toContain('needs BOTH')
        ->and($run['output'])->toContain('impersonator.enter')
        ->and($run['output'])->toContain('impersonator.mode.full')
        // A warning, not a failure: it may well be configured correctly.
        ->and($run['exit'])->toBe(0);
});

it('reports the base policy as allowing any registered mode', function (): void {
    // Keyed on the active policy rather than on whether spatie is installed, because the policy is
    // what actually decides — and an install naming RbacPolicy without spatie still enforces
    // per-mode permissions.
    expect(doctorRun()['output'])->toContain('does not check per-mode permissions');
});

it('warns about approval without approver notifications', function (): void {
    config()->set('impersonator.approval.require', true);
    config()->set('impersonator.notifications.approvals.enabled', false);

    doctor()
        ->expectsOutputToContain('approver notifications are off')
        ->assertSuccessful();
});

it('reports no conflicting impersonation package', function (): void {
    doctor()
        ->expectsOutputToContain('No other impersonation package detected')
        ->assertSuccessful();
});

it('warns about a conflicting package an application declared itself', function (): void {
    // The list is config-driven so an application can add whatever it knows conflicts — a Filament
    // plugin, an internal package — without waiting on a release here.
    config()->set('impersonator.doctor.conflicting_packages', [
        User::class => 'acme/legacy-impersonate',
    ]);

    $run = doctorRun();

    expect($run['output'])->toContain('acme/legacy-impersonate')
        // A warning, never a failure: two packages can coexist.
        ->and($run['exit'])->toBe(0);
});

// ── about ───────────────────────────────────────────────────────────────────

it('adds an about panel', function (): void {
    $this->artisan('about --only=impersonator')
        ->expectsOutputToContain('Driver')
        ->expectsOutputToContain('session')
        ->assertSuccessful();
});

it('never puts the audit hash key in the about output', function (): void {
    // `about` output is what people paste into bug reports.
    config()->set('impersonator.audit.tamper_evident', true);
    config()->set('impersonator.audit.hash_key', 'super-secret-key-that-must-not-leak');

    $this->artisan('about --only=impersonator')->assertSuccessful();

    expect(app(Kernel::class)->output())
        ->not->toContain('super-secret-key-that-must-not-leak');
});
