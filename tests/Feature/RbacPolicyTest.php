<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\RbacUser;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;

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
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 5);
    // Select the RBAC layer explicitly: the package is duck-typed, so it does not need
    // spatie installed, and auto-detection keys on that provider being present.
    config()->set('laranail.impersonator.authorization.policy', RbacPolicy::class);
    config()->set('laranail.impersonator.authorization.roles.levels', []);
    config()->set('laranail.impersonator.authorization.roles.protected', []);

    RbacUser::$registered = [];

    // Both permissions: `default_mode` is `full`, and the enter permission alone is
    // deliberately not enough — see the defence-in-depth test below.
    $this->admin = RbacUser::create([
        'name'        => 'Admin',
        'permissions' => ['impersonator.enter', 'impersonator.mode.full'],
    ]);
    $this->target = RbacUser::create(['name' => 'Customer']);
});

afterEach(function (): void {
    RbacUser::$registered = [];
});

function decide(RbacUser $impersonator, RbacUser $target, ?string $mode = null): Decision
{
    return app(ImpersonationManager::class)->canImpersonate($target, $mode, $impersonator);
}

it('selects the RBAC policy when configured', function (): void {
    expect(app(AuthorizationPolicy::class))->toBeInstanceOf(RbacPolicy::class);
});

it('rejects a configured policy that is not a policy', function (): void {
    config()->set('laranail.impersonator.authorization.policy', User::class);

    expect(fn () => app(AuthorizationPolicy::class))->toThrow(InvalidArgumentException::class);
});

// ── the enter permission ────────────────────────────────────────────────────

it('allows an operator holding the enter permission', function (): void {
    expect(decide($this->admin, $this->target)->allowed)->toBeTrue();
});

it('refuses an operator without the enter permission', function (): void {
    $nobody = RbacUser::create(['name' => 'Nobody', 'permissions' => []]);

    expect(decide($nobody, $this->target)->code)->toBe(Decision::MISSING_PERMISSION);
});

it('honours a renamed enter permission', function (): void {
    config()->set('laranail.impersonator.authorization.permissions.enter', 'acme.support.impersonate');
    $operator = RbacUser::create([
        'name'        => 'Op',
        'permissions' => ['acme.support.impersonate', 'impersonator.mode.full'],
    ]);

    expect(decide($operator, $this->target)->allowed)->toBeTrue()
        ->and(decide($this->admin, $this->target)->code)->toBe(Decision::MISSING_PERMISSION);
});

it('treats an unregistered permission as not held rather than erroring', function (): void {
    // spatie throws for a permission that was never seeded; a missing seed row must not
    // become a 500 on an unrelated request.
    RbacUser::$registered = ['something.else'];

    expect(decide($this->admin, $this->target)->code)->toBe(Decision::MISSING_PERMISSION);
});

// ── per-mode permissions ────────────────────────────────────────────────────

it('gates each mode behind its own permission', function (): void {
    // The rule that pins junior staff to read_only.
    $junior = RbacUser::create([
        'name'        => 'Junior',
        'permissions' => ['impersonator.enter', 'impersonator.mode.read_only'],
    ]);

    expect(decide($junior, $this->target, 'read_only')->allowed)->toBeTrue()
        ->and(decide($junior, $this->target, 'full')->code)->toBe(Decision::MISSING_MODE_PERMISSION)
        ->and(decide($junior, $this->target, 'limited')->code)->toBe(Decision::MISSING_MODE_PERMISSION);
});

it('allows a senior operator every mode they hold', function (): void {
    $senior = RbacUser::create([
        'name'        => 'Senior',
        'permissions' => [
            'impersonator.enter',
            'impersonator.mode.read_only',
            'impersonator.mode.limited',
            'impersonator.mode.full',
        ],
    ]);

    foreach (['read_only', 'limited', 'full'] as $mode) {
        expect(decide($senior, $this->target, $mode)->allowed)->toBeTrue();
    }
});

it('honours a custom mode permission template', function (): void {
    config()->set('laranail.impersonator.authorization.permissions.mode', 'acme.imp.%s');
    $operator = RbacUser::create([
        'name'        => 'Op',
        'permissions' => ['impersonator.enter', 'acme.imp.full'],
    ]);

    expect(decide($operator, $this->target, 'full')->allowed)->toBeTrue();
});

it('reports mode availability without impersonating, for a UI', function (): void {
    $junior = RbacUser::create([
        'name'        => 'Junior',
        'permissions' => ['impersonator.enter', 'impersonator.mode.read_only'],
    ]);

    $manager = app(ImpersonationManager::class);

    expect($manager->canUseMode('read_only', $junior)->allowed)->toBeTrue()
        ->and($manager->canUseMode('full', $junior)->allowed)->toBeFalse();
});

// ── protected roles ─────────────────────────────────────────────────────────

it('never allows a protected role to be impersonated', function (): void {
    config()->set('laranail.impersonator.authorization.roles.protected', ['super-admin']);
    $founder = RbacUser::create(['name' => 'Founder', 'roles' => ['super-admin']]);

    expect(decide($this->admin, $founder)->code)->toBe(Decision::PROTECTED_ROLE);
});

it('protects a role regardless of how privileged the impersonator is', function (): void {
    // A property of the target, not a comparison — no amount of privilege gets past it.
    config()->set('laranail.impersonator.authorization.roles.protected', ['super-admin']);
    $god = RbacUser::create([
        'name'        => 'God',
        'permissions' => ['impersonator.enter', 'impersonator.mode.full'],
        'roles'       => ['super-admin'],
    ]);
    $founder = RbacUser::create(['name' => 'Founder', 'roles' => ['super-admin']]);

    expect(decide($god, $founder)->code)->toBe(Decision::PROTECTED_ROLE);
});

it('leaves unprotected targets alone', function (): void {
    config()->set('laranail.impersonator.authorization.roles.protected', ['super-admin']);
    $staff = RbacUser::create(['name' => 'Staff', 'roles' => ['support']]);

    expect(decide($this->admin, $staff)->allowed)->toBeTrue();
});

// ── hierarchy ───────────────────────────────────────────────────────────────

it('requires the impersonator to outrank the target', function (): void {
    config()->set('laranail.impersonator.authorization.roles.levels', ['admin' => 80, 'support' => 40]);

    $admin = RbacUser::create([
        'name'        => 'Admin',
        'permissions' => ['impersonator.enter', 'impersonator.mode.full'],
        'roles'       => ['admin'],
    ]);
    $support = RbacUser::create([
        'name'        => 'Support',
        'permissions' => ['impersonator.enter', 'impersonator.mode.full'],
        'roles'       => ['support'],
    ]);

    expect(decide($admin, $support)->allowed)->toBeTrue()
        ->and(decide($support, $admin)->code)->toBe(Decision::HIERARCHY_VIOLATION);
});

it('refuses a sideways impersonation between peers', function (): void {
    config()->set('laranail.impersonator.authorization.roles.levels', ['support' => 40]);

    $perms = ['impersonator.enter', 'impersonator.mode.full'];
    $a = RbacUser::create(['name' => 'A', 'permissions' => $perms, 'roles' => ['support']]);
    $b = RbacUser::create(['name' => 'B', 'permissions' => $perms, 'roles' => ['support']]);

    expect(decide($a, $b)->code)->toBe(Decision::HIERARCHY_VIOLATION);
});

it('skips the hierarchy check when neither side is ranked', function (): void {
    // A comparison between two unranked users has no meaningful answer, and denying
    // would break every install that never configured levels.
    config()->set('laranail.impersonator.authorization.roles.levels', ['admin' => 80]);

    expect(decide($this->admin, $this->target)->allowed)->toBeTrue();
});

it('uses a configured closure in preference to the built-in comparison', function (): void {
    config()->set('laranail.impersonator.authorization.roles.levels', ['support' => 40]);
    config()->set('laranail.impersonator.authorization.roles.hierarchy', fn (): bool => true);

    $a = RbacUser::create([
        'name'        => 'A',
        'permissions' => ['impersonator.enter', 'impersonator.mode.full'],
        'roles'       => ['support'],
    ]);
    $b = RbacUser::create(['name' => 'B', 'roles' => ['support']]);

    expect(decide($a, $b)->allowed)->toBeTrue();
});

it('fails closed when a custom hierarchy rule returns something other than true', function (): void {
    // This is the one place an application can widen access, so anything ambiguous
    // denies.
    config()->set('laranail.impersonator.authorization.roles.hierarchy', fn (): ?bool => null);

    expect(decide($this->admin, $this->target)->code)->toBe(Decision::HIERARCHY_VIOLATION);
});

it('fails closed when a custom hierarchy rule throws', function (): void {
    config()->set('laranail.impersonator.authorization.roles.hierarchy', function (): bool {
        throw new RuntimeException('boom');
    });

    expect(decide($this->admin, $this->target)->code)->toBe(Decision::HIERARCHY_VIOLATION);
});

it('fails closed when a custom hierarchy rule is not callable', function (): void {
    config()->set('laranail.impersonator.authorization.roles.hierarchy', 'not-a-class');

    expect(decide($this->admin, $this->target)->code)->toBe(Decision::HIERARCHY_VIOLATION);
});

// ── revoke and audit permissions ────────────────────────────────────────────

it('gates revocation behind its own permission', function (): void {
    $policy = app(AuthorizationPolicy::class);
    $identities = app(ImpersonationManager::class)->identities();

    $revoker = RbacUser::create(['name' => 'Revoker', 'permissions' => ['impersonator.revoke']]);

    expect($policy->authorizeRevoke($identities->fromUser($revoker), 'any')->allowed)->toBeTrue()
        ->and($policy->authorizeRevoke($identities->fromUser($this->admin), 'any')->code)
        ->toBe(Decision::MISSING_PERMISSION);
});

it('gates audit access behind its own permission', function (): void {
    $policy = app(AuthorizationPolicy::class);
    $identities = app(ImpersonationManager::class)->identities();

    $viewer = RbacUser::create(['name' => 'Viewer', 'permissions' => ['impersonator.audit.view']]);

    expect($policy->authorizeAuditAccess($identities->fromUser($viewer))->allowed)->toBeTrue()
        ->and($policy->authorizeAuditAccess($identities->fromUser($this->admin))->code)
        ->toBe(Decision::MISSING_PERMISSION);
});

// ── the always-on rules still apply ─────────────────────────────────────────

it('still refuses self-impersonation with every permission held', function (): void {
    $god = RbacUser::create([
        'name'        => 'God',
        'permissions' => ['impersonator.enter', 'impersonator.mode.full'],
    ]);

    expect(decide($god, $god)->code)->toBe(Decision::SELF_IMPERSONATION);
});

it('ignores the RBAC rules for a model with no permission API', function (): void {
    // Requiring every user model to implement one would make an RBAC package a hard
    // dependency of this one.
    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);

    $plainAdmin = User::create(['name' => 'Plain admin']);
    $plainTarget = User::create(['name' => 'Plain target']);

    expect(app(ImpersonationManager::class)->canImpersonate($plainTarget, null, $plainAdmin)->allowed)
        ->toBeTrue();
});

it('requires the enter permission and the mode permission, not either one', function (): void {
    // Defence in depth, and the sharp edge worth stating: granting `impersonator.enter`
    // alone gives an operator nothing, because every impersonation carries a mode and
    // each mode is gated separately. The doctor command warns when the enter permission
    // exists but no mode permission does.
    $enterOnly = RbacUser::create(['name' => 'Enter only', 'permissions' => ['impersonator.enter']]);
    $modeOnly = RbacUser::create(['name' => 'Mode only', 'permissions' => ['impersonator.mode.full']]);

    expect(decide($enterOnly, $this->target)->code)->toBe(Decision::MISSING_MODE_PERMISSION)
        ->and(decide($modeOnly, $this->target)->code)->toBe(Decision::MISSING_PERMISSION)
        ->and(decide($this->admin, $this->target)->allowed)->toBeTrue();
});
