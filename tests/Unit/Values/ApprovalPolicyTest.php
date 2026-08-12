<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalState;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalVerdict;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalDecision;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalPolicy;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;

/*
| The approval chain's arithmetic, with no container and no database.
|
| Every rule here was a choice with a plausible alternative, so each has a test naming what the
| alternative would have cost.
*/

function decision(int $reviewer, ?string $role = null, bool $approved = true): ApprovalDecision
{
    return new ApprovalDecision(
        reviewer: new Identity('user', $reviewer),
        verdict: $approved ? ApprovalVerdict::Approved : ApprovalVerdict::Denied,
        decidedAt: new DateTimeImmutable('2026-08-12 10:00:00'),
        role: $role,
    );
}

it('needs one reviewer by default', function (): void {
    $policy = new ApprovalPolicy;

    expect($policy->required())->toBe(1)
        ->and($policy->isSingleReviewer())->toBeTrue()
        ->and($policy->stateFor([]))->toBe(ApprovalState::Pending)
        ->and($policy->stateFor([decision(2)]))->toBe(ApprovalState::Approved);
});

it('leaves a chain short of quorum partially approved', function (): void {
    // Not `Pending`, because an approver's queue needs to tell "nobody has looked" from "somebody
    // has and it is short". And not `Approved`, or one approval on a two-reviewer policy would be a
    // spendable permit.
    $policy = new ApprovalPolicy(quorum: 2);

    expect($policy->stateFor([decision(2)]))->toBe(ApprovalState::PartiallyApproved)
        ->and($policy->stateFor([decision(2), decision(3)]))->toBe(ApprovalState::Approved);
});

it('treats one denial as terminal however many approvals precede it', function (): void {
    // The asymmetry that makes the control fail closed: a reviewer who spots a problem does not have
    // to persuade the others.
    $policy = new ApprovalPolicy(quorum: 3);

    expect($policy->stateFor([decision(2), decision(3), decision(4, approved: false)]))
        ->toBe(ApprovalState::Denied)
        // Order must not matter either.
        ->and($policy->stateFor([decision(4, approved: false), decision(2), decision(3)]))
        ->toBe(ApprovalState::Denied)
        ->and(ApprovalVerdict::Denied->isTerminal())->toBeTrue()
        ->and(ApprovalVerdict::Approved->isTerminal())->toBeFalse();
});

it('takes quorum as an independent floor over the role total', function (): void {
    // `max(quorum, sum(roles))`. A policy asking for three reviewers of whom one must be an auditor
    // needs three — if the role map silently overrode quorum, it would need one.
    $policy = new ApprovalPolicy(quorum: 3, roles: ['auditor' => 1]);

    expect($policy->required())->toBe(3)
        ->and($policy->stateFor([decision(2, 'auditor')]))->toBe(ApprovalState::PartiallyApproved)
        ->and($policy->stateFor([decision(2, 'auditor'), decision(3)]))->toBe(ApprovalState::PartiallyApproved)
        ->and($policy->stateFor([decision(2, 'auditor'), decision(3), decision(4)]))->toBe(ApprovalState::Approved);
});

it('takes the role total when it exceeds quorum', function (): void {
    $policy = new ApprovalPolicy(quorum: 1, roles: ['manager' => 1, 'auditor' => 1]);

    expect($policy->required())->toBe(2)
        ->and($policy->isSingleReviewer())->toBeFalse();
});

it('refuses to be satisfied by the right count in the wrong roles', function (): void {
    // Three managers must not satisfy a policy that asked for an auditor. Checking the count alone
    // is the mistake this guards.
    $policy = new ApprovalPolicy(quorum: 2, roles: ['manager' => 1, 'auditor' => 1]);

    $twoManagers = [decision(2, 'manager'), decision(3, 'manager')];

    expect(count($twoManagers))->toBe($policy->required())
        ->and($policy->satisfiedBy($twoManagers))->toBeFalse()
        ->and($policy->outstandingRoles($twoManagers))->toBe(['auditor' => 1])
        ->and($policy->stateFor($twoManagers))->toBe(ApprovalState::PartiallyApproved);
});

it('lets one reviewer fill exactly one role slot', function (): void {
    // The rule that makes role slots mean anything. A person holding both roles satisfies one of
    // them; without this, a two-role policy is satisfiable by one person and the separation of
    // duties is theatre.
    $policy = new ApprovalPolicy(roles: ['manager' => 1, 'auditor' => 1]);

    // Recorded against `manager`, so `auditor` is still outstanding even though this reviewer
    // holds it.
    $both = [decision(2, 'manager')];

    expect($policy->outstandingRoles($both))->toBe(['auditor' => 1])
        ->and($policy->satisfiedBy($both))->toBeFalse()
        // And they cannot be offered the other slot by decision count either.
        ->and($policy->slotsFor(['manager', 'auditor'], $both))->toBe(['auditor']);
});

it('reports what is outstanding, so a queue can say more than a number', function (): void {
    $policy = new ApprovalPolicy(quorum: 3, roles: ['auditor' => 1, 'manager' => 2]);
    $recorded = [decision(2, 'manager')];

    expect($policy->required())->toBe(3)
        ->and($policy->outstandingCount($recorded))->toBe(2)
        ->and($policy->outstandingRoles($recorded))->toBe(['auditor' => 1, 'manager' => 1]);
});

it('offers a reviewer only the slots still open', function (): void {
    $policy = new ApprovalPolicy(roles: ['manager' => 1, 'auditor' => 1]);

    expect($policy->slotsFor(['manager', 'auditor'], []))->toBe(['manager', 'auditor'])
        ->and($policy->slotsFor(['manager'], [decision(2, 'manager')]))->toBe([])
        // A role the policy never asked for is not a slot.
        ->and($policy->slotsFor(['analyst'], []))->toBe([])
        // No role map means every reviewer is interchangeable.
        ->and(new ApprovalPolicy(quorum: 2)->slotsFor(['manager'], []))->toBe([]);
});

it('reads a config entry, discarding anything unusable', function (): void {
    $policy = ApprovalPolicy::fromArray([
        'quorum' => '2',
        'roles' => ['manager' => 1, 'auditor' => '2', 'ignored' => 0, '' => 3, 'bad' => 'x'],
    ]);

    expect($policy->quorum)->toBe(2)
        ->and($policy->roles)->toBe(['manager' => 1, 'auditor' => 2])
        ->and($policy->required())->toBe(3);
});

it('floors quorum at one so a request is never born satisfied', function (): void {
    // A zero quorum with no roles would mean "approval required" and "nothing required" at the same
    // time, which reads as a permit that needed nobody.
    foreach ([0, -5, null, 'nonsense'] as $value) {
        expect(ApprovalPolicy::fromArray(['quorum' => $value])->required())->toBe(1);
    }

    expect(ApprovalPolicy::fromArray([])->required())->toBe(1);
});

it('keeps a partially approved chain open but not decided', function (): void {
    // Both halves matter. Open, or the sweeper expires it out from under reviewers still working
    // through it. Not decided, or a single approval on a two-reviewer policy behaves like a permit.
    expect(ApprovalState::PartiallyApproved->isOpen())->toBeTrue()
        ->and(ApprovalState::PartiallyApproved->isDecided())->toBeFalse()
        ->and(ApprovalState::PartiallyApproved->acceptsDecisions())->toBeTrue()
        ->and(ApprovalState::Denied->acceptsDecisions())->toBeFalse()
        ->and(ApprovalState::Approved->acceptsDecisions())->toBeFalse();
});
