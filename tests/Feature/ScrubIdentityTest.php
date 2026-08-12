<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

/*
| GDPR erasure against a trail that is deliberately denormalised.
|
| The labels are PII on purpose: a row has to stay readable after a rename or a deletion. That design
| is right, and it is exactly why an erasure request needs a tool — otherwise only time-based retention
| clears the name.
*/

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('impersonator.audit.tamper_evidence', true);
    config()->set('impersonator.audit.hash_key', str_repeat('k', 64));
    config()->set('impersonator.limits.state_cache.ttl', 0);

    $this->admin = User::create(['name' => 'Alice Admin']);
    $this->target = User::create(['name' => 'Bob Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

it('nulls the name and keeps the row', function (): void {
    Impersonator::enter($this->target);
    $auditId = Impersonator::current()?->auditId;
    Impersonator::leave();

    $this->artisan('laranail::impersonator.scrub-identity', ['identity' => 'user:' . $this->target->getKey()])
        ->assertSuccessful();

    $row = ImpersonationAudit::query()->find($auditId);

    // Erasure of personal data does not extend to erasing the record that an account was accessed —
    // that record is the controller's own evidence of processing.
    expect($row)->not->toBeNull()
        ->and($row?->getAttribute('target_label'))->toBeNull()
        ->and($row?->getAttribute('impersonatable_id'))->toBe((string) $this->target->getKey())
        // The other party's name is untouched: this is one identity's erasure, not the row's.
        ->and($row?->getAttribute('impersonator_label'))->toBe('Alice Admin');
});

it('leaves the hash chain verifiable', function (): void {
    // The property that made this implementable at all: the labels are not among the chained facts, so
    // scrubbing them cannot make `verify-audit` report tampering that never happened.
    Impersonator::enter($this->target);
    Impersonator::leave();

    $this->artisan('laranail::impersonator.scrub-identity', ['identity' => 'user:' . $this->target->getKey()])
        ->assertSuccessful();

    $this->artisan('laranail::impersonator.verify-audit')->assertSuccessful();
});

it('scrubs an identity that appears on both sides of a row', function (): void {
    // Nulling only the matched side would leave the name behind on the other.
    Impersonator::enter($this->target);
    $auditId = Impersonator::current()?->auditId;
    Impersonator::leave();

    $this->artisan('laranail::impersonator.scrub-identity', ['identity' => 'user:' . $this->admin->getKey()])
        ->assertSuccessful();

    $row = ImpersonationAudit::query()->find($auditId);

    expect($row?->getAttribute('impersonator_label'))->toBeNull()
        ->and($row?->getAttribute('target_label'))->toBe('Bob Customer');
});

it('writes nothing on a dry run', function (): void {
    Impersonator::enter($this->target);
    $auditId = Impersonator::current()?->auditId;
    Impersonator::leave();

    $this->artisan('laranail::impersonator.scrub-identity', [
        'identity' => 'user:' . $this->target->getKey(),
        '--dry-run' => true,
    ])->assertSuccessful();

    expect(ImpersonationAudit::query()->find($auditId)?->getAttribute('target_label'))->toBe('Bob Customer');
});

it('refuses a reference that is not type:id', function (): void {
    // A bare id would be ambiguous across models, and guessing the type is how the wrong person's name
    // gets erased.
    $this->artisan('laranail::impersonator.scrub-identity', ['identity' => '9902'])->assertFailed();
});

it('reports plainly when nothing mentions that identity', function (): void {
    $this->artisan('laranail::impersonator.scrub-identity', ['identity' => 'user:999999'])
        ->expectsOutputToContain('No audit rows mention that identity.')
        ->assertSuccessful();
});
