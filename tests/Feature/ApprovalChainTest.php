<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\RbacUser;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalState;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalDecision;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ApprovalRequired;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Services\ApprovalService;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ApprovalNotDecidable;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;

/*
| Multi-reviewer approval chains.
|
| The single-reviewer flow is covered by ApprovalWorkflowTest. This file is about what a *second*
| reviewer changes, and every case here is a property that would be quietly wrong if the chain were
| implemented as "overwrite the decision columns".
*/

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->json('roles')->nullable();
        $table->json('permissions')->nullable();
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => RbacUser::class]);
    config()->set('auth.providers.users.model', RbacUser::class);
    config()->set('laranail.impersonator.authorization.policy', RbacPolicy::class);
    config()->set('laranail.impersonator.approval.require', true);
    config()->set('laranail.impersonator.approval.except_modes', []);
    config()->set('laranail.impersonator.limits.state_cache.ttl', 0);

    // Two reviewers, one of each role, plus a requester who holds everything.
    $this->requester = RbacUser::create([
        'name'        => 'Requester',
        'roles'       => ['manager', 'auditor'],
        'permissions' => ['impersonator.enter', 'impersonator.mode.full', 'impersonator.approve'],
    ]);
    $this->manager = RbacUser::create([
        'name'        => 'Manager',
        'roles'       => ['manager'],
        'permissions' => ['impersonator.approve'],
    ]);
    $this->auditor = RbacUser::create([
        'name'        => 'Auditor',
        'roles'       => ['auditor'],
        'permissions' => ['impersonator.approve'],
    ]);
    $this->target = RbacUser::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->requester);
});

/**
 * Open a request by attempting an impersonation that needs approval.
 *
 * The target is passed rather than read from `test()`: a bare function is not bound to the test case,
 * so `test()->target` resolves to the case object itself.
 */
function openChainRequest(RbacUser $target): string
{
    try {
        Impersonator::enter($target, mode: 'full', reason: 'Ticket #1');
    } catch (ApprovalRequired $e) {
        return $e->approvalId;
    }

    throw new RuntimeException('the impersonation was not held for approval');
}

function chainIdentityOf(RbacUser $user): Identity
{
    return Impersonator::identities()->fromUser($user);
}

it('leaves a chain short of quorum partially approved, and refuses to spend it', function (): void {
    // The central property. One approval on a two-reviewer policy is not a permit — if `consume()`
    // accepted it, the second reviewer would be decoration.
    config()->set('laranail.impersonator.approval.policies', ['default' => ['quorum' => 2]]);

    $id = openChainRequest($this->target);
    $store = app(ApprovalStore::class);

    $after = app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager));

    expect($after->state)->toBe(ApprovalState::PartiallyApproved)
        ->and($after->state->isOpen())->toBeTrue()
        ->and($after->state->isDecided())->toBeFalse()
        // Not spendable, and not reported as usable either.
        ->and($store->consume($after->fingerprint(), chainIdentityOf($this->requester)))->toBeNull()
        ->and($store->findUsable($after->fingerprint(), chainIdentityOf($this->requester)))->toBeNull();

    // The second approval closes it.
    $closed = app(ApprovalService::class)->grant($id, chainIdentityOf($this->auditor));

    expect($closed->state)->toBe(ApprovalState::Approved)
        ->and($store->findUsable($closed->fingerprint(), chainIdentityOf($this->requester)))->not->toBeNull();
});

it('treats one denial as terminal even after approvals are recorded', function (): void {
    config()->set('laranail.impersonator.approval.policies', ['default' => ['quorum' => 3]]);

    $id = openChainRequest($this->target);

    app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager));
    $denied = app(ApprovalService::class)->deny($id, chainIdentityOf($this->auditor), 'Not justified');

    expect($denied->state)->toBe(ApprovalState::Denied)
        ->and($denied->state->isOpen())->toBeFalse()
        // And the chain is closed to further decisions, so a third reviewer cannot overrule the denial.
        ->and($denied->state->acceptsDecisions())->toBeFalse();

    expect(fn () => app(ApprovalService::class)->grant($id, chainIdentityOf($this->requester)))
        ->toThrow(ApprovalNotDecidable::class);
});

it('records every reviewer rather than overwriting the previous one', function (): void {
    // What the child table exists for. Three columns on the parent row could hold one answer, so the
    // second reviewer would have erased the first — losing the only fact an audit of a four-eyes
    // control is actually about.
    config()->set('laranail.impersonator.approval.policies', ['default' => ['quorum' => 2]]);

    $id = openChainRequest($this->target);

    app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager), 'Checked the ticket');
    app(ApprovalService::class)->grant($id, chainIdentityOf($this->auditor), 'Sampled the account');

    $decisions = app(ApprovalStore::class)->decisions($id);

    expect($decisions)->toHaveCount(2)
        // Oldest first: the sequence is the interesting part.
        ->and($decisions[0]->reviewer->id)->toBe((string) $this->manager->getKey())
        ->and($decisions[0]->note)->toBe('Checked the ticket')
        ->and($decisions[1]->reviewer->id)->toBe((string) $this->auditor->getKey())
        ->and($decisions[1]->note)->toBe('Sampled the account')
        ->and($decisions[0]->approved())->toBeTrue();
});

it('refuses a second decision from the same reviewer', function (): void {
    config()->set('laranail.impersonator.approval.policies', ['default' => ['quorum' => 3]]);

    $id = openChainRequest($this->target);

    app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager));

    // The guard reports it; the database is what makes it impossible.
    expect(fn () => app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager)))
        ->toThrow(ApprovalNotDecidable::class);

    expect(app(ApprovalStore::class)->decisions($id))->toHaveCount(1);
});

it('lets the database, not a guard, arbitrate a duplicate reviewer', function (): void {
    // Asserted at the store, below the action's guard. A check in PHP cannot close this: two requests
    // from one approver both read no prior decision and both write, so one reviewer counts twice
    // toward quorum. The unique index is what makes it impossible rather than unlikely.
    config()->set('laranail.impersonator.approval.policies', ['default' => ['quorum' => 3]]);

    $id = openChainRequest($this->target);
    $store = app(ApprovalStore::class);
    $manager = chainIdentityOf($this->manager);

    expect($store->grant($id, $manager))->not->toBeNull()
        // The second call bypasses every guard and still cannot land a row.
        ->and($store->grant($id, $manager))->toBeNull()
        ->and($store->decisions($id))->toHaveCount(1);
});

it('lets one reviewer fill only one role slot', function (): void {
    // The rule that makes role slots mean anything. The requester holds both roles — so does nobody
    // else here — so this uses a reviewer who holds both and checks they cannot satisfy both.
    config()->set('laranail.impersonator.approval.policies', [
        'default' => ['quorum' => 2, 'roles' => ['manager' => 1, 'auditor' => 1]],
    ]);

    $both = RbacUser::create([
        'name'        => 'Both',
        'roles'       => ['manager', 'auditor'],
        'permissions' => ['impersonator.approve'],
    ]);

    $id = openChainRequest($this->target);

    $after = app(ApprovalService::class)->grant($id, chainIdentityOf($both));

    expect($after->state)->toBe(ApprovalState::PartiallyApproved);

    $decisions = app(ApprovalStore::class)->decisions($id);

    expect($decisions)->toHaveCount(1)
        // One slot recorded, not two.
        ->and($decisions[0]->role)->toBeIn(['manager', 'auditor']);

    // And they cannot come back for the other slot.
    expect(fn () => app(ApprovalService::class)->grant($id, chainIdentityOf($both)))
        ->toThrow(ApprovalNotDecidable::class);
});

it('refuses a reviewer who holds no role the chain is waiting on', function (): void {
    config()->set('laranail.impersonator.approval.policies', [
        'default' => ['quorum' => 1, 'roles' => ['auditor' => 1]],
    ]);

    $id = openChainRequest($this->target);

    // A manager cannot fill an auditor slot, however many approvals the count would allow.
    try {
        app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager));
        $this->fail('a manager filled an auditor slot');
    } catch (ImpersonationDenied $e) {
        expect($e->code())->toBe(Decision::APPROVER_NOT_ELIGIBLE);
    }

    expect(app(ApprovalStore::class)->decisions($id))->toBeEmpty();
});

it('still refuses the requester however many roles they hold', function (): void {
    // The requester holds both required roles and the approve permission. Self-approval is checked
    // before anything about roles, because a four-eyes flow where one pair of eyes can be both pairs
    // is a delay rather than a control.
    config()->set('laranail.impersonator.approval.policies', [
        'default' => ['quorum' => 2, 'roles' => ['manager' => 1, 'auditor' => 1]],
    ]);

    $id = openChainRequest($this->target);

    expect(fn () => app(ApprovalService::class)->grant($id, chainIdentityOf($this->requester)))
        ->toThrow(ApprovalNotDecidable::class);

    expect(app(ApprovalStore::class)->decisions($id))->toBeEmpty();
});

it('lets an application refuse a reviewer with its own rule', function (): void {
    config()->set('laranail.impersonator.approval.policies', ['default' => ['quorum' => 1]]);

    // "Must not be the auditor", standing in for a relationship this package cannot model.
    Impersonator::approvalEligibilityUsing(
        fn (object $reviewer): bool => $reviewer->getKey() !== $this->auditor->getKey(),
    );

    $id = openChainRequest($this->target);

    try {
        app(ApprovalService::class)->grant($id, chainIdentityOf($this->auditor));
        $this->fail('an ineligible reviewer decided the request');
    } catch (ImpersonationDenied $e) {
        expect($e->code())->toBe(Decision::APPROVER_NOT_ELIGIBLE);
    }

    // The manager still can, so the rule narrowed rather than blocked.
    expect(app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager))->state)
        ->toBe(ApprovalState::Approved);
});

it('fails closed when an eligibility rule returns something other than true', function (): void {
    config()->set('laranail.impersonator.approval.policies', ['default' => ['quorum' => 1]]);

    // A truthy string is not a yes: the point of registering a rule is that the package cannot judge
    // the relationship, so anything ambiguous has to refuse.
    foreach (['yes', 1, [], null] as $value) {
        Impersonator::approvalEligibilityUsing(fn (): mixed => $value);

        $id = openChainRequest($this->target);

        expect(fn () => app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager)))
            ->toThrow(ImpersonationDenied::class);

        expect(app(ApprovalStore::class)->decisions($id))->toBeEmpty();
    }
});

it('fails closed when an eligibility rule throws', function (): void {
    config()->set('laranail.impersonator.approval.policies', ['default' => ['quorum' => 1]]);

    Impersonator::approvalEligibilityUsing(function (): bool {
        throw new RuntimeException('the directory is down');
    });

    $id = openChainRequest($this->target);

    expect(fn () => app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager)))
        ->toThrow(ImpersonationDenied::class);
});

it('applies a per-mode policy, falling back to default', function (): void {
    // A `full`-access request warranting two reviewers while read-only work needs one is the ordinary
    // shape of this control.
    config()->set('laranail.impersonator.approval.policies', [
        'default' => ['quorum' => 1],
        'full'    => ['quorum' => 2],
    ]);

    $id = openChainRequest($this->target);

    expect(app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager))->state)
        ->toBe(ApprovalState::PartiallyApproved);
});

it('reports the closing decision as the rollup, and not before', function (): void {
    // `decided_by` is published API shape. It names the reviewer who closed the chain — and stays null
    // while the request is still waiting, where naming one reviewer would read as "decided by them".
    config()->set('laranail.impersonator.approval.policies', ['default' => ['quorum' => 2]]);

    $id = openChainRequest($this->target);

    $partial = app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager), 'first');

    expect($partial->decidedBy)->toBeNull()
        ->and($partial->decidedAt)->toBeNull();

    $closed = app(ApprovalService::class)->grant($id, chainIdentityOf($this->auditor), 'second');

    expect($closed->decidedBy?->id)->toBe((string) $this->auditor->getKey())
        ->and($closed->decisionNote)->toBe('second')
        ->and($closed->decidedAt)->not->toBeNull();
});

it('names the denier as the rollup even when approvals came first', function (): void {
    config()->set('laranail.impersonator.approval.policies', ['default' => ['quorum' => 3]]);

    $id = openChainRequest($this->target);

    app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager), 'looks fine');
    app(ApprovalService::class)->deny($id, chainIdentityOf($this->auditor), 'no justification');

    $denied = app(ApprovalStore::class)->find($id);

    expect($denied?->decidedBy?->id)->toBe((string) $this->auditor->getKey())
        ->and($denied?->decisionNote)->toBe('no justification');
});

it('reports chain progress and every decision through the service', function (): void {
    // "Two of three, still needs an auditor" is the sentence a reviewer can act on. "Pending" is not,
    // which is why a count alone was never enough.
    config()->set('laranail.impersonator.approval.policies', [
        'default' => ['quorum' => 3, 'roles' => ['manager' => 1, 'auditor' => 1]],
    ]);

    $id = openChainRequest($this->target);
    $service = app(ApprovalService::class);

    $service->grant($id, chainIdentityOf($this->manager));

    $request = $service->find($id);
    $progress = $service->progress($request);

    expect($progress['required'])->toBe(3)
        ->and($progress['approved'])->toBe(1)
        ->and($progress['outstanding'])->toBe(2)
        ->and($progress['outstanding_roles'])->toBe(['auditor' => 1])
        ->and($progress['policy']['quorum'])->toBe(3)
        ->and($service->decisions($id))->toHaveCount(1);
});

it('never puts the fingerprint in a decision projection', function (): void {
    // An approval queue is a screen operators holding `approve` but not `enter` can see. The
    // fingerprint is what a permit is matched on, so it is the one field that must not travel.
    config()->set('laranail.impersonator.approval.policies', ['default' => ['quorum' => 1]]);

    $id = openChainRequest($this->target);
    app(ApprovalService::class)->grant($id, chainIdentityOf($this->manager), 'fine');

    $request = app(ApprovalService::class)->find($id);
    $encoded = json_encode([
        'request'   => $request->toArray(),
        'decisions' => array_map(
            static fn (ApprovalDecision $decision): array => $decision->toArray(),
            app(ApprovalService::class)->decisions($id),
        ),
    ]);

    expect($encoded)->not->toContain($request->fingerprint())
        ->and($encoded)->not->toContain('fingerprint');
});
