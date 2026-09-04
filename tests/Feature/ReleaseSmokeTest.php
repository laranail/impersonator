<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;
use Illuminate\Database\Schema\Blueprint;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;
use Simtabi\Laranail\Impersonator\Core\Support\FailureReport;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;

/*
| The release gate: the things a clean install has to do on the first try.
|
| Every assertion here corresponds to something that has actually broken on a previous release of this
| package — a facade import that did not resolve, a migration that would not run twice, a doctor that
| crashed on the misconfigured install somebody ran it to diagnose, an `about` panel that printed the
| audit hash key. Cheap to run, and it is the last thing between a green suite and a bad tag.
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
    config()->set('laranail.impersonator.limits.state_cache.ttl', 0);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

it('creates every table the package needs', function (): void {
    foreach ([
        'impersonator_audits',
        'impersonator_audit_events',
        'impersonator_tokens',
        'impersonator_approval_requests',
        'impersonator_approval_decisions',
    ] as $table) {
        expect(Schema::hasTable($table))->toBeTrue("missing table [{$table}]");
    }
});

it('performs a whole impersonation on a default configuration', function (): void {
    // Nothing configured beyond the allowlist: this is what a fresh install does.
    $outcome = Impersonator::enter($this->target, reason: 'Smoke test');

    expect($outcome->isStarted())->toBeTrue()
        ->and(Impersonator::isImpersonating())->toBeTrue()
        ->and(Impersonator::target()?->getKey())->toBe($this->target->getKey())
        // The operator is still attributable, which is the correctness fix the package exists for.
        ->and(Impersonator::actor()?->getKey())->toBe($this->admin->getKey());

    expect(Impersonator::extendSession()->granted())->toBeTrue();

    $session = Impersonator::leave();

    expect($session?->hasEnded())->toBeTrue()
        ->and(Impersonator::isImpersonating())->toBeFalse();
});

it('boots with nothing degraded', function (): void {
    // The CI canary. A degradable boot operation that failed leaves an application that starts cleanly
    // and quietly lacks a feature, which is the failure mode the whole FailurePolicy exists for.
    expect(app(FailureReport::class)->isHealthy())->toBeTrue();
});

it('runs the doctor to completion on a default install', function (): void {
    $this->artisan('laranail::impersonator.doctor')->assertSuccessful();
});

it('runs the doctor without crashing on a deliberately broken install', function (): void {
    // The one case it has to handle well: somebody runs this *because* the install is broken. Tamper
    // evidence on with no key makes the audit store throw on construction, which used to take the
    // doctor down with it.
    config()->set('laranail.impersonator.audit.tamper_evidence', true);
    config()->set('laranail.impersonator.audit.hash_key', null);
    config()->set('laranail.impersonator.targets.allowlist', ['ghost' => 'App\\Models\\NotInstalled']);
    config()->set('laranail.impersonator.api.enabled', true);
    config()->set('laranail.impersonator.api.middleware', ['api']);

    // Non-zero is correct here — it found real failures. What matters is that it *reported* them.
    $this->artisan('laranail::impersonator.doctor')->assertFailed();
});

it('never prints the audit hash key in the about panel', function (): void {
    $secret = 'sk-' . str_repeat('z', 60);

    config()->set('laranail.impersonator.audit.tamper_evidence', true);
    config()->set('laranail.impersonator.audit.hash_key', $secret);

    $this->artisan('about')->assertSuccessful()->doesntExpectOutputToContain($secret);
});

it('verifies its own audit chain end to end', function (): void {
    config()->set('laranail.impersonator.audit.tamper_evidence', true);
    config()->set('laranail.impersonator.audit.hash_key', str_repeat('k', 64));

    Impersonator::enter($this->target);
    Impersonator::leave();

    $this->artisan('laranail::impersonator.verify-audit')->assertSuccessful();
});

it('registers every documented publish tag', function (): void {
    // A documented `vendor:publish --tag=…` that does not exist is a broken install instruction.
    $groups = ServiceProvider::$publishGroups;

    foreach ([
        'impersonator-config',
        'impersonator-migrations',
        'impersonator-views',
        'impersonator-lang',
    ] as $tag) {
        expect($groups)->toHaveKey($tag);
    }
});
