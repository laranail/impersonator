<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalState;
use Simtabi\Laranail\Impersonator\Core\Values\ExtensionPolicy;
use Simtabi\Laranail\Impersonator\Core\Values\Guards;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Laravel\Audit\ConcurrencyLimitReached;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

/*
| The concurrency guarantees, tested against a database that actually locks.
|
| `max_active_per_impersonator` is a count-then-insert: read how many are open, refuse if at the
| cap, otherwise write. That is a race two simultaneous requests both win unless the read holds a
| lock — which is why the store wraps it in a transaction with `lockForUpdate()`.
|
| SQLite compiles that lock to an empty string. So this whole file skips there rather than passing,
| because a green run on SQLite would be evidence of nothing at all.
*/

uses()->group('locking');

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('impersonator.limits.state_cache.ttl', 0);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);
    $this->second = User::create(['name' => 'Second']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

it('requests a row lock when counting active impersonations', function (): void {
    // The assertion that the guarantee is actually asked for. Without the lock clause in the
    // emitted SQL, the cap is a read-then-write and two requests can both pass it.
    requiresRowLocks();

    config()->set('impersonator.limits.max_active_per_impersonator', 2);

    $locked = [];
    DB::listen(function ($query) use (&$locked): void {
        if (str_contains(strtolower($query->sql), 'for update')) {
            $locked[] = $query->sql;
        }
    });

    Impersonator::enter($this->target);

    expect($locked)->not->toBeEmpty()
        ->and(implode(' ', $locked))->toContain('impersonator_audits');
});

it('enforces the cap inside the locked transaction', function (): void {
    // Tested at the store rather than through `enter()`, deliberately. The policy's own cap check
    // runs first and is advisory; and once nesting is allowed the operator's identity has already
    // shifted to the target, so a second `enter()` counts the wrong person. The store is the layer
    // that holds the lock, so it is the layer whose refusal is worth proving.
    requiresRowLocks();

    $store = app(AuditStore::class);
    $identities = Impersonator::identities();

    $request = Impersonator::buildRequest(
        target: $this->target,
        impersonator: $this->admin,
    );

    config()->set('impersonator.limits.max_active_per_impersonator', 1);

    $store->open($request);

    // The same operator, still holding one open row: the locked count refuses the second.
    expect(fn () => $store->open($request))
        ->toThrow(ConcurrencyLimitReached::class);
});

it('locks the chain head while computing a digest', function (): void {
    // The third locked path, and the one that matters most for correctness: the HMAC chain reads the
    // previous row's digest to compute the next. Two impersonations opening at once must not both
    // read the same predecessor, or they produce two rows claiming the same position and the chain
    // no longer verifies.
    requiresRowLocks();

    config()->set('impersonator.limits.max_active_per_impersonator', 5);
    config()->set('impersonator.audit.tamper_evident', true);
    config()->set('impersonator.audit.hash_key', str_repeat('k', 64));

    // One row first, so there is a chain head to lock.
    Impersonator::enter($this->target);
    Impersonator::leave();

    $locked = [];
    DB::listen(function ($query) use (&$locked): void {
        if (str_contains(strtolower($query->sql), 'for update')) {
            $locked[] = $query->sql;
        }
    });

    Impersonator::enter($this->second);

    expect(implode(' ', $locked))->toContain('hash');
});

it('requests a row lock before deciding whether more time may be granted', function (): void {
    requiresRowLocks();

    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    $auditId = (string) Impersonator::current()?->auditId;
    $locked = [];

    DB::listen(function ($query) use (&$locked): void {
        if (str_contains(strtolower($query->sql), 'for update')) {
            $locked[] = $query->sql;
        }
    });

    app(AuditStore::class)->extend($auditId, new ExtensionPolicy, now()->toDateTimeImmutable());

    // The caps are evaluated against the row *inside* the lock. Read it unlocked and two
    // concurrent requests both see the same remaining allowance and both spend it.
    expect($locked)->not->toBeEmpty();
});

it('spends one allowance when two extensions race', function (): void {
    requiresRowLocks();

    config()->set('impersonator.limits.extension.max', 1);
    config()->set('impersonator.limits.extension.max_total_duration', null);

    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    $auditId = (string) Impersonator::current()?->auditId;
    $store = app(AuditStore::class);
    $policy = new ExtensionPolicy(max: 1, maxTotalMinutes: null);
    $now = now()->toDateTimeImmutable();

    // Sequential here rather than genuinely parallel, because two PHP processes cannot share
    // Testbench's application. What this proves is the half that a lock cannot: the count is
    // read and written in the same transaction, so the second attempt sees the first.
    $first = $store->extend($auditId, $policy, $now);
    $second = $store->extend($auditId, $policy, $now);

    expect($first->granted())->toBeTrue()
        ->and($second->denied())->toBeTrue()
        ->and($second->session?->extensions)->toBe(1);
});

it('locks the approval row before recounting a chain', function (): void {
    requiresRowLocks();

    config()->set('impersonator.approval.policies', ['default' => ['quorum' => 2]]);

    $request = new ImpersonationRequest(
        impersonator: new Identity('user', 1),
        target: new Identity('user', 2),
        mode: Mode::of(Mode::FULL),
        guards: new Guards('web', 'web'),
        driver: 'session',
        adapter: 'session',
    );

    $store = app(ApprovalStore::class);
    $opened = $store->open($request, now()->addMinutes(15)->toDateTimeImmutable());

    $locked = [];

    DB::listen(function ($query) use (&$locked): void {
        if (str_contains(strtolower($query->sql), 'for update')) {
            $locked[] = $query->sql;
        }
    });

    $store->grant($opened->id, new Identity('user', 3));

    // The quorum recount is the race a chain introduces: two reviewers granting at once must not both
    // read "one of two" and leave the request short, nor both flip it to Approved. The parent row is
    // locked so the recount serialises.
    expect($locked)->not->toBeEmpty();
});

it('lands exactly one state transition when two reviewers grant', function (): void {
    requiresRowLocks();

    config()->set('impersonator.approval.policies', ['default' => ['quorum' => 2]]);

    $request = new ImpersonationRequest(
        impersonator: new Identity('user', 1),
        target: new Identity('user', 2),
        mode: Mode::of(Mode::FULL),
        guards: new Guards('web', 'web'),
        driver: 'session',
        adapter: 'session',
    );

    $store = app(ApprovalStore::class);
    $opened = $store->open($request, now()->addMinutes(15)->toDateTimeImmutable());

    // Sequential here rather than genuinely parallel, because two PHP processes cannot share
    // Testbench's application. What this proves is the half a lock cannot: each grant recounts from
    // every decision written so far, so the second sees the first and the chain closes once.
    $first = $store->grant($opened->id, new Identity('user', 3));
    $second = $store->grant($opened->id, new Identity('user', 4));

    expect($first?->state)->toBe(ApprovalState::PartiallyApproved)
        ->and($second?->state)->toBe(ApprovalState::Approved)
        ->and($store->decisions($opened->id))->toHaveCount(2);
});
