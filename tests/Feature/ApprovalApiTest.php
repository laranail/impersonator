<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalState;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ApprovalRequired;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationApprovalRequest;
use Simtabi\Laranail\Impersonator\Laravel\Services\ApprovalService;
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

    config()->set('laranail.impersonator.targets.allowlist', ['user' => RbacUser::class]);
    config()->set('auth.providers.users.model', RbacUser::class);
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 10);
    config()->set('laranail.impersonator.limits.state_cache.ttl', 0);
    config()->set('laranail.impersonator.authorization.policy', RbacPolicy::class);
    config()->set('laranail.impersonator.authorization.roles.levels', []);
    config()->set('laranail.impersonator.authorization.roles.protected', []);
    config()->set('laranail.impersonator.approval.require', true);

    config()->set('laranail.impersonator.api.enabled', true);
    config()->set('laranail.impersonator.api.middleware', ['api']);

    RbacUser::$registered = [];

    $this->operator = RbacUser::create([
        'name' => 'Operator',
        'permissions' => ['impersonator.enter', 'impersonator.mode.full'],
    ]);

    $this->approver = RbacUser::create([
        'name' => 'Approver',
        'permissions' => ['impersonator.approve'],
    ]);

    $this->target = RbacUser::create(['name' => 'Customer']);

    require dirname(__DIR__, 2).'/routes/api.php';

    $this->startSession();
    Auth::guard('web')->setUser($this->operator);
});

afterEach(function (): void {
    RbacUser::$registered = [];
});

function approvalUrl(string $path): string
{
    return '/impersonator/api/v1/'.ltrim($path, '/');
}

/** Open a pending request the way the API does, and return its id. */
function openRequest(RbacUser $target): string
{
    $response = test()->postJson(approvalUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $target->getKey(),
    ]);

    $response->assertStatus(202);

    return $response->json('approval.id');
}

// ── starting under approval ─────────────────────────────────────────────────

it('answers 202 rather than 403 when approval is required', function (): void {
    // The operator holds every permission the request needed and nothing was refused — a 403
    // would send them asking for permissions they already have.
    $response = $this->postJson(approvalUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
    ]);

    $response->assertStatus(202)
        ->assertJsonPath('reason', 'approval_required')
        ->assertJsonPath('approval.id', fn ($id): bool => is_string($id) && $id !== '')
        ->assertJsonPath('approval.expires_at', fn ($at): bool => $at !== null);

    expect(Impersonator::isImpersonating())->toBeFalse();
});

it('never returns a credential alongside a pending approval', function (): void {
    // The 202 body is not a started impersonation, so it must carry nothing spendable.
    $body = $this->postJson(approvalUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
    ])->assertStatus(202)->content();

    expect($body)->not->toContain('credential')
        ->and($body)->not->toContain('accept_url');
});

// ── the queue ───────────────────────────────────────────────────────────────

it('shows the queue to an approver', function (): void {
    openRequest($this->target);

    Auth::guard('web')->setUser($this->approver);

    $this->getJson(approvalUrl('approvals'))
        ->assertOk()
        ->assertJsonPath('meta.count', 1)
        ->assertJsonPath('data.0.state', 'pending')
        ->assertJsonPath('data.0.mode', 'full');
});

it('refuses the queue to an operator who only holds the enter permission', function (): void {
    // Entering does not confer approving. If it did, any two support staff could clear each
    // other's break-glass requests.
    openRequest($this->target);

    $this->getJson(approvalUrl('approvals'))->assertForbidden();
});

it('never exposes the fingerprint or the stored request in a listing', function (): void {
    openRequest($this->target);

    Auth::guard('web')->setUser($this->approver);

    $body = $this->getJson(approvalUrl('approvals'))->assertOk()->content();

    // The fingerprint is a verifier, and an approval queue is visible to operators who hold
    // `approve` but not `enter` — they have no business holding anything spendable.
    expect($body)->not->toContain('fingerprint')
        ->and($body)->not->toContain('credential');
});

it('lets an operator see their own requests without any permission', function (): void {
    $id = openRequest($this->target);

    // Still the requester, who holds no approve permission.
    $this->getJson(approvalUrl('approvals/mine'))
        ->assertOk()
        ->assertJsonPath('meta.count', 1)
        ->assertJsonPath('data.0.id', $id);
});

it('does not leak other operators requests through mine', function (): void {
    openRequest($this->target);

    Auth::guard('web')->setUser($this->approver);

    $this->getJson(approvalUrl('approvals/mine'))
        ->assertOk()
        ->assertJsonPath('meta.count', 0);
});

it('resolves mine ahead of the id parameter', function (): void {
    // A literal segment declared after `{approval}` would be swallowed by it, and a caller
    // asking for their own requests would get a 404 for an approval id of "mine".
    openRequest($this->target);

    $this->getJson(approvalUrl('approvals/mine'))->assertOk()->assertJsonPath('meta.count', 1);
});

it('404s for an unknown approval id', function (): void {
    Auth::guard('web')->setUser($this->approver);

    $this->getJson(approvalUrl('approvals/nope'))->assertNotFound();
});

// ── deciding ────────────────────────────────────────────────────────────────

it('grants and then lets the requester enter once', function (): void {
    $id = openRequest($this->target);

    Auth::guard('web')->setUser($this->approver);

    $this->postJson(approvalUrl("approvals/{$id}/grant"), ['note' => 'Incident #77'])
        ->assertOk()
        ->assertJsonPath('data.state', 'approved')
        ->assertJsonPath('data.decision_note', 'Incident #77');

    Auth::guard('web')->setUser($this->operator);

    $this->postJson(approvalUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
    ])->assertCreated()->assertJsonPath('data.pending', false);

    expect(app(ApprovalService::class)->find($id)->state)->toBe(ApprovalState::Consumed);
});

it('denies with a reason and blocks the entry', function (): void {
    $id = openRequest($this->target);

    Auth::guard('web')->setUser($this->approver);

    $this->postJson(approvalUrl("approvals/{$id}/deny"), ['note' => 'Not warranted'])
        ->assertOk()
        ->assertJsonPath('data.state', 'denied');

    Auth::guard('web')->setUser($this->operator);

    $this->postJson(approvalUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
    ])->assertStatus(202);

    expect(Impersonator::isImpersonating())->toBeFalse();
});

it('refuses a self-approval with a 409', function (): void {
    $id = openRequest($this->target);

    // Give the requester the approve permission too, so only the four-eyes rule is refusing.
    $this->operator->update(['permissions' => [
        'impersonator.enter', 'impersonator.mode.full', 'impersonator.approve',
    ]]);

    $this->postJson(approvalUrl("approvals/{$id}/grant"))
        ->assertStatus(409)
        ->assertJsonPath('reason', 'self_approval');

    expect(app(ApprovalService::class)->find($id)->state)->toBe(ApprovalState::Pending);
});

it('refuses a second decision with a 409', function (): void {
    $id = openRequest($this->target);

    Auth::guard('web')->setUser($this->approver);

    $this->postJson(approvalUrl("approvals/{$id}/deny"))->assertOk();

    // An approver who said no must not be overruled by a later yes.
    $this->postJson(approvalUrl("approvals/{$id}/grant"))
        ->assertStatus(409)
        ->assertJsonPath('reason', 'already_decided');
});

it('refuses to decide without the approve permission', function (): void {
    $id = openRequest($this->target);

    $colleague = RbacUser::create([
        'name' => 'Colleague',
        'permissions' => ['impersonator.enter', 'impersonator.mode.full'],
    ]);
    Auth::guard('web')->setUser($colleague);

    $this->postJson(approvalUrl("approvals/{$id}/grant"))->assertForbidden();

    expect(app(ApprovalService::class)->find($id)->state)->toBe(ApprovalState::Pending);
});

it('bounds the decision note', function (): void {
    $id = openRequest($this->target);

    Auth::guard('web')->setUser($this->approver);

    $this->postJson(approvalUrl("approvals/{$id}/grant"), ['note' => str_repeat('x', 501)])
        ->assertStatus(422)
        ->assertJsonValidationErrors('note');
});

it('refuses an expired request with a 409', function (): void {
    config()->set('laranail.impersonator.approval.ttl', 5);

    $id = openRequest($this->target);

    $this->travel(6)->minutes();

    Auth::guard('web')->setUser($this->approver);

    $this->postJson(approvalUrl("approvals/{$id}/grant"))
        ->assertStatus(409)
        ->assertJsonPath('reason', 'expired');
});

it('requires authentication throughout', function (): void {
    $id = openRequest($this->target);

    Auth::guard('web')->logout();

    $this->getJson(approvalUrl('approvals'))->assertForbidden();
    $this->postJson(approvalUrl("approvals/{$id}/grant"))->assertForbidden();
});

it('links the approval to the impersonation it produced', function (): void {
    $id = openRequest($this->target);

    Auth::guard('web')->setUser($this->approver);
    $this->postJson(approvalUrl("approvals/{$id}/grant"))->assertOk();

    Auth::guard('web')->setUser($this->operator);
    $auditId = $this->postJson(approvalUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
    ])->assertCreated()->json('data.impersonation.id');

    // Both directions, so an auditor holding either row can reach the other.
    $this->getJson(approvalUrl("approvals/{$id}"))
        ->assertOk()
        ->assertJsonPath('data.audit_id', $auditId);

    expect(ImpersonationApprovalRequest::query()->count())->toBe(1);
});

it('is absent when the approval feature is off but the api is on', function (): void {
    // Turning approval off must not remove the queue endpoints: an install that disables the
    // requirement still has historical requests an auditor may need to read.
    config()->set('laranail.impersonator.approval.require', false);

    Auth::guard('web')->setUser($this->approver);

    $this->getJson(approvalUrl('approvals'))->assertOk()->assertJsonPath('meta.count', 0);
});

it('still enters directly when approval is not required', function (): void {
    config()->set('laranail.impersonator.approval.require', false);

    $this->postJson(approvalUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
    ])->assertCreated();

    expect(Impersonator::isImpersonating())->toBeTrue()
        ->and(ImpersonationApprovalRequest::query()->count())->toBe(0);
});

it('leaves the facade path throwing rather than returning a 202 shape', function (): void {
    // The exception is the contract for a programmatic caller; the 202 is only how HTTP renders
    // it. A facade that silently returned "no impersonation" would be far worse.
    expect(fn () => Impersonator::enter($this->target))->toThrow(ApprovalRequired::class);
});
