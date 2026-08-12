<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalState;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalDenied;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalGranted;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalRequested;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationStarted;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ApprovalNotDecidable;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ApprovalRequired;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationApprovalRequest;
use Simtabi\Laranail\Impersonator\Laravel\Notifications\ApprovalDecided;
use Simtabi\Laranail\Impersonator\Laravel\Notifications\ApprovalRequestedNotification;
use Simtabi\Laranail\Impersonator\Laravel\Services\ApprovalService;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\PlainUser;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\RbacUser;

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->json('permissions')->nullable();
        $table->json('roles')->nullable();
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('impersonator.targets.allowlist', ['user' => RbacUser::class]);
    config()->set('auth.providers.users.model', RbacUser::class);
    config()->set('impersonator.limits.max_active_per_impersonator', 10);
    config()->set('impersonator.limits.state_cache.ttl', 0);
    config()->set('impersonator.authorization.policy', RbacPolicy::class);
    config()->set('impersonator.authorization.roles.levels', []);
    config()->set('impersonator.authorization.roles.protected', []);

    config()->set('impersonator.approval.require', true);

    RbacUser::$registered = [];

    $this->operator = RbacUser::create([
        'name' => 'Operator',
        'permissions' => ['impersonator.enter', 'impersonator.mode.full', 'impersonator.mode.read_only'],
    ]);

    // The approver holds `approve` and deliberately *not* `enter`: authorising access and
    // using it are separate roles, and the test suite should not be able to confuse them.
    $this->approver = RbacUser::create([
        'name' => 'Approver',
        'permissions' => ['impersonator.approve'],
    ]);

    $this->target = RbacUser::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->operator);
});

afterEach(function (): void {
    RbacUser::$registered = [];
});

function approvals(): ApprovalService
{
    return app(ApprovalService::class);
}

/** The permit fingerprint for an operator/target/mode triple. */
function permitFor(RbacUser $operator, RbacUser $target, string $mode = 'full'): string
{
    $identities = Impersonator::identities();

    return ApprovalRequest::fingerprintFor(
        $identities->fromUser($operator),
        $identities->fromUser($target),
        $mode,
    );
}

// ── the gate ────────────────────────────────────────────────────────────────

it('refuses to enter and opens a pending request instead', function (): void {
    Event::fake([ApprovalRequested::class, ImpersonationStarted::class]);

    $thrown = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $thrown = $e;
    }

    expect($thrown)->toBeInstanceOf(ApprovalRequired::class)
        ->and($thrown->code())->toBe('approval_required')
        // Nothing was provisioned. A break-glass flow that impersonated first and asked
        // afterwards would not be a control at all.
        ->and(Impersonator::isImpersonating())->toBeFalse();

    Event::assertDispatched(ApprovalRequested::class);
    Event::assertNotDispatched(ImpersonationStarted::class);

    $pending = approvals()->find($thrown->approvalId);

    expect($pending)->not->toBeNull()
        ->and($pending->state)->toBe(ApprovalState::Pending)
        ->and($pending->target->id)->toBe((string) $this->target->getKey());
});

it('does nothing when approval is not required', function (): void {
    config()->set('impersonator.approval.require', false);

    Impersonator::enter($this->target);

    expect(Impersonator::isImpersonating())->toBeTrue()
        ->and(ImpersonationApprovalRequest::query()->count())->toBe(0);
});

it('exempts read_only by default', function (): void {
    // The default exemption is the point of the feature: requiring a second person for
    // routine read-only work is how a four-eyes control becomes a rubber stamp.
    Impersonator::enter($this->target, mode: 'read_only');

    expect(Impersonator::isImpersonating())->toBeTrue()
        ->and(ImpersonationApprovalRequest::query()->count())->toBe(0);
});

it('requires approval for an exempted mode once the exemption is removed', function (): void {
    config()->set('impersonator.approval.except_modes', []);

    expect(fn () => Impersonator::enter($this->target, mode: 'read_only'))
        ->toThrow(ApprovalRequired::class);
});

it('runs the authorization stack before opening a request', function (): void {
    // An operator who may not impersonate at all must be refused outright, not handed a
    // queue entry — which would teach them the account exists and invite an approver to
    // grant something the policy will refuse a second time anyway.
    $nobody = RbacUser::create(['name' => 'Nobody', 'permissions' => []]);
    Auth::guard('web')->setUser($nobody);

    expect(fn () => Impersonator::enter($this->target))->toThrow(ImpersonationDenied::class)
        ->and(ImpersonationApprovalRequest::query()->count())->toBe(0);
});

it('reuses the open request rather than queueing a duplicate', function (): void {
    $first = null;
    $second = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $first = $e->approvalId;
    }

    approvals()->grant($first, $this->approver);

    try {
        // Approved but unspent. Asking again should surface the same permit, not open a
        // second row for the approver to wade through.
        Impersonator::enter($this->target, mode: 'read_only');
    } catch (ApprovalRequired $e) {
        $second = $e->approvalId;
    }

    // read_only is exempt, so that entry succeeded and nothing new was queued.
    expect($second)->toBeNull()
        ->and(ImpersonationApprovalRequest::query()->count())->toBe(1);
});

// ── granting ────────────────────────────────────────────────────────────────

it('lets an approved operator enter, exactly once', function (): void {
    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    Event::fake([ApprovalGranted::class]);
    approvals()->grant($approvalId, $this->approver, 'Incident #77');
    Event::assertDispatched(ApprovalGranted::class);

    $outcome = Impersonator::enter($this->target);

    expect(Impersonator::isImpersonating())->toBeTrue()
        ->and(approvals()->find($approvalId)->state)->toBe(ApprovalState::Consumed)
        // Both directions of the link, so an auditor holding either row can reach the other.
        ->and(approvals()->find($approvalId)->auditId)->toBe($outcome->auditId())
        ->and($outcome->session->metadata['approval_id'] ?? null)->toBe($approvalId);

    Impersonator::leave();

    // The permit is spent. A second entry needs a second approval, or one approval becomes
    // standing access to that account for as long as the row survives.
    expect(fn () => Impersonator::enter($this->target))->toThrow(ApprovalRequired::class);
});

it('records who approved it', function (): void {
    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    $granted = approvals()->grant($approvalId, $this->approver, 'Signed off');

    expect($granted->decidedBy?->id)->toBe((string) $this->approver->getKey())
        ->and($granted->decisionNote)->toBe('Signed off')
        ->and($granted->decidedAt)->not->toBeNull();
});

// ── the four-eyes rule ──────────────────────────────────────────────────────

it('refuses to let the requester approve their own request', function (): void {
    // The entire point of the control. A flow where one pair of eyes can be both pairs is
    // a delay, not a control — so this is enforced against the row, not left to the UI.
    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    // Give the requester the approve permission too, so the only thing refusing is the
    // requester-is-not-the-approver rule.
    $this->operator->update(['permissions' => [
        'impersonator.enter', 'impersonator.mode.full', 'impersonator.approve',
    ]]);

    $thrown = null;

    try {
        approvals()->grant($approvalId, $this->operator);
    } catch (ApprovalNotDecidable $e) {
        $thrown = $e;
    }

    expect($thrown)->toBeInstanceOf(ApprovalNotDecidable::class)
        ->and($thrown->reason())->toBe('self_approval')
        ->and(approvals()->find($approvalId)->state)->toBe(ApprovalState::Pending);
});

it('requires the approve permission, which entering does not confer', function (): void {
    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    // A colleague who may impersonate but was never given `approve`. If entering implied
    // approving, any two support staff could clear each other's requests.
    $colleague = RbacUser::create([
        'name' => 'Colleague',
        'permissions' => ['impersonator.enter', 'impersonator.mode.full'],
    ]);

    expect(fn (): ApprovalRequest => approvals()->grant($approvalId, $colleague))->toThrow(ImpersonationDenied::class)
        ->and(approvals()->find($approvalId)->state)->toBe(ApprovalState::Pending);
});

// ── the permit is bound to what was approved ────────────────────────────────

it('cannot be spent on a higher mode than was approved', function (): void {
    // Mode escalation through the approval flow. An approval for read-only support work
    // must not become full write access by changing one form field on the way back.
    config()->set('impersonator.approval.except_modes', []);

    $approvalId = null;

    try {
        Impersonator::enter($this->target, mode: 'read_only');
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    approvals()->grant($approvalId, $this->approver);

    expect(fn () => Impersonator::enter($this->target, mode: 'full'))->toThrow(ApprovalRequired::class)
        ->and(approvals()->find($approvalId)->state)->toBe(ApprovalState::Approved);
});

it('cannot be spent on a different target', function (): void {
    $other = RbacUser::create(['name' => 'Someone Else']);

    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    approvals()->grant($approvalId, $this->approver);

    expect(fn () => Impersonator::enter($other))->toThrow(ApprovalRequired::class)
        ->and(approvals()->find($approvalId)->state)->toBe(ApprovalState::Approved);
});

it('cannot be spent by a different operator', function (): void {
    // A permit belongs to the operator who asked for it. One colleague spending another's
    // approval would destroy the record of who was authorised to do what.
    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    approvals()->grant($approvalId, $this->approver);

    $colleague = RbacUser::create([
        'name' => 'Colleague',
        'permissions' => ['impersonator.enter', 'impersonator.mode.full'],
    ]);
    Auth::guard('web')->setUser($colleague);

    expect(fn () => Impersonator::enter($this->target))->toThrow(ApprovalRequired::class)
        ->and(approvals()->find($approvalId)->state)->toBe(ApprovalState::Approved);
});

// ── denial and expiry ───────────────────────────────────────────────────────

it('cannot enter on a denied request', function (): void {
    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    Event::fake([ApprovalDenied::class]);
    approvals()->deny($approvalId, $this->approver, 'Not warranted');
    Event::assertDispatched(ApprovalDenied::class);

    expect(approvals()->find($approvalId)->state)->toBe(ApprovalState::Denied);

    // A fresh request is opened rather than the denied one being reused.
    $second = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $second = $e->approvalId;
    }

    expect($second)->not->toBe($approvalId);
});

it('cannot re-decide a decided request', function (): void {
    // An approver who said no must not be overruled by a later yes, and the same approval
    // must not be grantable twice.
    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    approvals()->deny($approvalId, $this->approver);

    expect(fn (): ApprovalRequest => approvals()->grant($approvalId, $this->approver))
        ->toThrow(ApprovalNotDecidable::class)
        ->and(approvals()->find($approvalId)->state)->toBe(ApprovalState::Denied);
});

it('will not decide or spend a request past its ttl', function (): void {
    config()->set('impersonator.approval.ttl', 15);

    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    $this->travel(16)->minutes();

    $thrown = null;

    try {
        approvals()->grant($approvalId, $this->approver);
    } catch (ApprovalNotDecidable $e) {
        $thrown = $e;
    }

    expect($thrown?->reason())->toBe('expired');
});

it('will not spend a permit that expired after it was granted', function (): void {
    // Expiry is enforced on read, so the TTL binds the whole flow rather than only the
    // window before a decision.
    config()->set('impersonator.approval.ttl', 15);

    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    approvals()->grant($approvalId, $this->approver);

    $this->travel(16)->minutes();

    expect(fn () => Impersonator::enter($this->target))->toThrow(ApprovalRequired::class);
});

it('sweeps stale requests and announces each one', function (): void {
    config()->set('impersonator.approval.ttl', 5);

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired) {
        // expected
    }

    $this->travel(6)->minutes();

    Event::fake([ApprovalDenied::class]);
    $expired = approvals()->expireStale();

    expect($expired)->toHaveCount(1)
        ->and($expired[0]->state)->toBe(ApprovalState::Expired);

    Event::assertDispatched(
        ApprovalDenied::class,
        // Announced as an expiry rather than a refusal: nobody said no, nobody answered.
        static fn (ApprovalDenied $event): bool => $event->expired && $event->deniedBy === null,
    );
});

// ── the store's atomicity ───────────────────────────────────────────────────

it('spends a permit exactly once under concurrent redemption', function (): void {
    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    approvals()->grant($approvalId, $this->approver);

    $store = app(ApprovalStore::class);
    $fingerprint = permitFor($this->operator, $this->target);
    $identity = Impersonator::identities()->fromUser($this->operator);

    // Two callers presenting the same permit. The conditional UPDATE is the arbitration,
    // so exactly one wins — a read-then-write would let both through.
    $first = $store->consume($fingerprint, $identity);
    $second = $store->consume($fingerprint, $identity);

    expect($first)->not->toBeNull()
        ->and($second)->toBeNull();
});

// ── the queue ───────────────────────────────────────────────────────────────

it('lists pending requests for an approver and the requester their own', function (): void {
    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired) {
        // expected
    }

    expect(approvals()->queue())->toHaveCount(1)
        ->and(approvals()->mine($this->operator))->toHaveCount(1)
        ->and(approvals()->mine($this->approver))->toHaveCount(0);
});

it('drops expired requests from the approver queue', function (): void {
    config()->set('impersonator.approval.ttl', 5);

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired) {
        // expected
    }

    $this->travel(6)->minutes();

    // A queue listing dead requests invites somebody to approve one and wonder why
    // nothing happened.
    expect(approvals()->queue())->toHaveCount(0);
});

it('reports whether an operator already holds a spendable permit', function (): void {
    expect(approvals()->hasPermit($this->target, 'full', $this->operator))->toBeFalse();

    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    expect(approvals()->hasPermit($this->target, 'full', $this->operator))->toBeFalse();

    approvals()->grant($approvalId, $this->approver);

    expect(approvals()->hasPermit($this->target, 'full', $this->operator))->toBeTrue()
        // Bound to the mode, so a read_only permit is not reported for full.
        ->and(approvals()->hasPermit($this->target, 'read_only', $this->operator))->toBeFalse();
});

// ── the record ──────────────────────────────────────────────────────────────

it('never exposes a credential or session id in the approval projection', function (): void {
    // An approval queue is a screen several operators can see, including ones holding
    // `approve` but not `enter` — who have no business holding anything spendable.
    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    $projection = approvals()->find($approvalId)->toArray();

    expect($projection)->not->toHaveKeys(['credential', 'credential_hash', 'session_id', 'fingerprint'])
        ->and(array_keys($projection))->toContain('requester', 'target', 'mode', 'state');
});

it('keeps the approved parameters rather than trusting the resubmission', function (): void {
    config()->set('impersonator.reason.require', true);

    $approvalId = null;

    try {
        Impersonator::enter($this->target, reason: 'Billing dispute #12');
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    $stored = approvals()->find($approvalId);

    expect($stored->reason)->toBe('Billing dispute #12')
        ->and($stored->request->reason)->toBe('Billing dispute #12')
        // Cast on the way in: the stored JSON preserves the integer key while the indexed
        // column holds a string, which is exactly why Identity compares ids loosely on their
        // PHP type. Asserting identity here would be asserting an accident of json_decode.
        ->and((string) $stored->request->target->id)->toBe((string) $this->target->getKey())
        ->and($stored->request->target->is($stored->target))->toBeTrue();
});

// ── notifications ───────────────────────────────────────────────────────────

it('notifies the configured approver addresses', function (): void {
    Notification::fake();

    config()->set('impersonator.notifications.approvals.enabled', true);
    config()->set('impersonator.notifications.approvals.mail', ['security@example.com']);

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired) {
        // expected
    }

    Notification::assertSentOnDemand(ApprovalRequestedNotification::class);
});

it('sends nothing to approvers until the channel is enabled', function (): void {
    Notification::fake();

    config()->set('impersonator.notifications.approvals.mail', ['security@example.com']);

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired) {
        // expected
    }

    Notification::assertNothingSent();
});

it('notifies resolved approvers but never the requester', function (): void {
    Notification::fake();

    config()->set('impersonator.notifications.approvals.enabled', true);

    $operator = $this->operator;
    $approver = $this->approver;

    // A resolver returning both, to prove the requester is filtered out. Mailing somebody an
    // approval prompt they cannot act on is noise that turns into a support ticket.
    config()->set(
        'impersonator.notifications.approvals.resolver',
        fn (): array => [$approver, $operator],
    );

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired) {
        // expected
    }

    Notification::assertSentTo($approver, ApprovalRequestedNotification::class);
    Notification::assertNotSentTo($operator, ApprovalRequestedNotification::class);
});

it('survives a resolver that throws', function (): void {
    Notification::fake();

    config()->set('impersonator.notifications.approvals.enabled', true);
    config()->set('impersonator.notifications.approvals.resolver', function (): array {
        throw new RuntimeException('directory unavailable');
    });

    // The row is already written and the operator is already waiting, so a broken resolver
    // must not turn a pending request into a 500.
    $thrown = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $thrown = $e;
    }

    expect($thrown)->toBeInstanceOf(ApprovalRequired::class)
        ->and(approvals()->find($thrown->approvalId))->not->toBeNull();
});

it('tells the requester the outcome of a decision', function (): void {
    Notification::fake();

    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    approvals()->grant($approvalId, $this->approver);

    Notification::assertSentTo(
        $this->operator,
        ApprovalDecided::class,
        static fn (ApprovalDecided $notification): bool => $notification->request->approved()
            && $notification->expired === false,
    );
});

it('tells the requester when nobody answered', function (): void {
    config()->set('impersonator.approval.ttl', 5);

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired) {
        // expected
    }

    $this->travel(6)->minutes();

    Notification::fake();
    approvals()->expireStale();

    Notification::assertSentTo(
        $this->operator,
        ApprovalDecided::class,
        static fn (ApprovalDecided $notification): bool => $notification->expired,
    );
});

it('can be told not to notify the requester', function (): void {
    Notification::fake();

    config()->set('impersonator.notifications.approvals.notify_requester', false);

    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    approvals()->grant($approvalId, $this->approver);

    Notification::assertNothingSent();
});

// ── the prune command ───────────────────────────────────────────────────────

it('expires stale requests through the console command', function (): void {
    config()->set('impersonator.approval.ttl', 5);

    $approvalId = null;

    try {
        Impersonator::enter($this->target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    $this->travel(6)->minutes();

    $this->artisan('laranail::impersonator.prune-approvals')
        ->expectsOutputToContain('1 impersonation approval request expired.')
        ->assertSuccessful();

    // Expired, not deleted: removing the record that somebody asked for access is exactly what
    // an auditor came to read.
    expect(approvals()->find($approvalId)->state)->toBe(ApprovalState::Expired)
        ->and(ImpersonationApprovalRequest::query()->count())->toBe(1);
});

it('reports when the command has nothing to do', function (): void {
    $this->artisan('laranail::impersonator.prune-approvals')
        ->expectsOutputToContain('No impersonation approval requests needed expiring.')
        ->assertSuccessful();
});

it('tolerates a requester who cannot be notified', function (): void {
    // A user model without Notifiable is a configuration gap worth a warning, never a reason
    // for the decision to fail — the approver already said yes, and the permit already exists.
    Notification::fake();

    config()->set('impersonator.targets.allowlist', ['user' => PlainUser::class]);
    config()->set('auth.providers.users.model', PlainUser::class);

    $operator = PlainUser::create(['name' => 'Plain Operator']);
    $target = PlainUser::create(['name' => 'Plain Customer']);
    Auth::guard('web')->setUser($operator);

    $approvalId = null;

    try {
        Impersonator::enter($target);
    } catch (ApprovalRequired $e) {
        $approvalId = $e->approvalId;
    }

    // The approver is still an RbacUser holding the permission, resolved by identity.
    $granted = approvals()->grant(
        $approvalId,
        Impersonator::identities()->fromUser($this->approver),
    );

    expect($granted->state)->toBe(ApprovalState::Approved);

    Notification::assertNothingSent();
});
