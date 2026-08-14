<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Laravel\Services\AuditService;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

/*
| The polymorphic columns.
|
| Two properties matter here and they pull in opposite directions. The `*_type` half must hold a
| morph **alias** and never a class name — that is the control that stops a crafted type naming an
| arbitrary class, and it is what lets a class be renamed without orphaning its history. The `*_id`
| half must stay a **string**, so one trail can hold an int-keyed User beside a UUID-keyed Vendor.
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

it('names the impersonated account by the ability that makes it eligible', function (): void {
    // The rename. `target` is what it is called in one request; `impersonatable` is what makes it
    // eligible at all, and the column is named for the durable fact.
    $columns = Schema::getColumnListing('impersonator_audits');

    expect($columns)->toContain('impersonatable_type', 'impersonatable_id')
        ->and($columns)->not->toContain('target_type', 'target_id')
        // The operator keeps its own name: an actor has no `-able` form.
        ->and($columns)->toContain('impersonator_type', 'impersonator_id')
        ->and($columns)->toContain('revoked_by_type', 'revoked_by_id');
});

it('uses the same pair on the approvals table', function (): void {
    $columns = Schema::getColumnListing('impersonator_approval_requests');

    expect($columns)->toContain('impersonatable_type', 'impersonatable_id')
        ->and($columns)->toContain('requester_type', 'requester_id')
        ->and($columns)->not->toContain('target_type', 'target_id')
        // `decided_by_*` moved to the decisions table when a second reviewer became possible: three
        // columns here could hold exactly one answer, so a second reviewer would have overwritten
        // the first.
        ->and($columns)->not->toContain('decided_by_type', 'decided_by_id', 'decision_note');
});

it('gives each reviewer their own row, with a morph pair', function (): void {
    $columns = Schema::getColumnListing('impersonator_approval_decisions');

    expect($columns)->toContain('approval_id', 'reviewer_type', 'reviewer_id')
        ->and($columns)->toContain('reviewer_role', 'verdict', 'note', 'decided_at');
});

it('stores the morph alias, never the class name', function (): void {
    // The injection control. A `*_type` holding a fully qualified class name is both a leak of the
    // application's internals into every audit export and a value that breaks on a rename.
    Impersonator::enter($this->target);

    $row = ImpersonationAudit::query()->find((string) Impersonator::current()?->auditId);

    expect($row?->getAttribute('impersonatable_type'))->toBe('user')
        ->and($row?->getAttribute('impersonator_type'))->toBe('user')
        ->and($row?->getAttribute('impersonatable_type'))->not->toContain('\\');
});

it('keeps the id half a string so mixed key types share one table', function (): void {
    // `$table->morphs()` would have typed this `unsignedBigInteger`, which makes a UUID-keyed model
    // unstorable — and a multi-model allowlist is the whole reason this table is polymorphic.
    Impersonator::enter($this->target);

    $row = ImpersonationAudit::query()->find((string) Impersonator::current()?->auditId);

    expect($row?->getAttribute('impersonatable_id'))->toBeString()
        ->toBe((string) $this->target->getKey());
});

it('resolves the impersonated account through the morph relation', function (): void {
    Impersonator::enter($this->target);

    $row = ImpersonationAudit::query()->find((string) Impersonator::current()?->auditId);

    expect($row?->impersonatable)->toBeInstanceOf(User::class)
        ->and($row?->impersonatable?->getKey())->toBe($this->target->getKey())
        ->and($row?->impersonator?->getKey())->toBe($this->admin->getKey());
});

it('resolves whoever revoked it through its own relation', function (): void {
    Impersonator::enter($this->target);

    $auditId = (string) Impersonator::current()?->auditId;
    app(AuditStore::class)->markRevoked($auditId, Impersonator::identities()->fromUser($this->admin));

    $row = ImpersonationAudit::query()->find($auditId);

    expect($row?->revokedBy)->toBeInstanceOf(User::class)
        ->and($row?->revokedBy?->getKey())->toBe($this->admin->getKey());
});

it('reads the renamed columns back into the session value object', function (): void {
    // The Core value object still calls it `target`, because a framework-free session has no notion
    // of a morph column. The mapping happens at the Eloquent boundary, which is where it belongs.
    Impersonator::enter($this->target);

    $session = ImpersonationAudit::query()
        ->find((string) Impersonator::current()?->auditId)
        ?->toSession();

    expect($session?->target->type)->toBe('user')
        ->and($session?->target->id)->toBe((string) $this->target->getKey())
        ->and($session?->impersonator->id)->toBe((string) $this->admin->getKey());
});

it('still filters by the public target field after the column rename', function (): void {
    // The regression the rename actually caused: the audit filter derived its column name from the
    // public filter name, so `?target=user:9` queried a column that no longer existed.
    Impersonator::enter($this->target);
    Impersonator::leave();

    $service = app(AuditService::class);

    expect($service->query(['target' => 'user:' . $this->target->getKey()])->count())->toBe(1)
        ->and($service->query(['target' => (string) $this->target->getKey()])->count())->toBe(1)
        ->and($service->query(['target' => 'user:999999'])->count())->toBe(0)
        ->and($service->query(['impersonator' => 'user:' . $this->admin->getKey()])->count())->toBe(1);
});

it('leaves the audit hash chain verifiable across the rename', function (): void {
    // The chained fact is keyed `target` and valued `type:id`. Only the columns it is read *from*
    // moved, so the digest of an existing row is unchanged — a rename must not read as tampering.
    config()->set('laranail.impersonator.audit.tamper_evidence', true);
    config()->set('laranail.impersonator.audit.hash_key', str_repeat('k', 64));

    Impersonator::enter($this->target);

    $store = app(AuditStore::class);
    $row = ImpersonationAudit::query()->find((string) Impersonator::current()?->auditId);
    $facts = $store->chainFactsFromRow($row);

    expect($facts)->toHaveKey('target')
        ->and($facts['target'])->toBe('user:' . $this->target->getKey())
        ->and($facts)->not->toHaveKey('impersonatable');
});

it('does not require a morph map by default', function (): void {
    // Off by default because `requireMorphMap()` is application-global: turning it on from a package
    // would make a host application's unrelated unmapped morphs start throwing on upgrade.
    expect(config('laranail.impersonator.morphs.require_map'))->toBeFalse()
        ->and(Relation::requiresMorphMap())->toBeFalse();
});
