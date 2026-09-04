<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Authorization;

use Closure;
use Throwable;
use Illuminate\Database\Eloquent\Model;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;

/**
 * The role-based layer, stacked on top of the always-on rules in BasePolicy.
 *
 * Deliberately duck-typed rather than coupled to spatie/laravel-permission. It calls
 * `hasPermissionTo()`, `hasRole()` and `getRoleNames()` when the model exposes them,
 * which is spatie's shape but also that of several other RBAC packages — and it means
 * this file needs no dependency, no `class_exists` dance, and can be tested without
 * installing anything. A model with none of those methods simply inherits the base
 * behaviour.
 *
 * Four rules, in cheapest-first order:
 *
 *  1. **The enter permission.** No permission, no impersonation at all.
 *  2. **Per-mode permission.** This is what pins junior support staff to `read_only`
 *     while a senior operator may pick `full`.
 *  3. **Protected roles.** Holders can never be impersonated, by anyone — including by
 *     somebody who holds every permission. It is a property of the target, not a
 *     comparison, so no amount of privilege gets past it.
 *  4. **Hierarchy.** The impersonator's highest role level must exceed the target's, so
 *     peers cannot impersonate each other sideways.
 *
 * Note what this does *not* do: it never grants the impersonated session the
 * impersonator's permissions. While impersonating, effective permissions are the
 * target's, narrowed further by the mode. Anything else would be privilege escalation
 * dressed up as support tooling.
 */
class RbacPolicy extends BasePolicy
{
    public function authorize(ImpersonationRequest $request): Decision
    {
        $base = parent::authorize($request);

        if ($base->denied()) {
            return $base;
        }

        return Decision::all([
            fn (): Decision => $this->checkEnterPermission($request->impersonator),
            fn (): Decision => $this->checkTargetNotProtected($request),
            fn (): Decision => $this->checkHierarchy($request),
        ]);
    }

    public function authorizeMode(Identity $impersonator, string $mode): Decision
    {
        $base = parent::authorizeMode($impersonator, $mode);

        if ($base->denied()) {
            return $base;
        }

        // The coarse gate before the narrow one. `authorizeMode` is reached from inside
        // the base chain, so without this an operator holding nothing at all would be
        // told they may not use `full` — when the real answer is that they may not
        // impersonate at all. The message an operator gets has to name the actual
        // problem, or they go asking for the wrong permission.
        $enter = $this->checkEnterPermission($impersonator);

        if ($enter->denied()) {
            return $enter;
        }

        $template = $this->settings->string('authorization.permissions.mode', 'impersonator.mode.%s');
        $permission = Mode::of($mode)->permission($template);

        return $this->requirePermission(
            $impersonator,
            $permission,
            Decision::MISSING_MODE_PERMISSION,
            sprintf('You are not permitted to use the [%s] impersonation mode.', $mode),
        );
    }

    public function authorizeRevoke(Identity $impersonator, string $auditId): Decision
    {
        return $this->requirePermission(
            $impersonator,
            $this->settings->string('authorization.permissions.revoke', 'impersonator.revoke'),
            Decision::MISSING_PERMISSION,
            'You are not permitted to revoke impersonations.',
        );
    }

    /**
     * Deliberately not satisfied by the enter permission.
     *
     * An operator who may impersonate does not thereby get to approve, because the whole point
     * of the control is that a second, differently-authorised person signs off. Making `enter`
     * imply `approve` would mean any two support staff could clear each other's break-glass
     * requests, which is a rubber stamp with extra steps.
     */
    public function authorizeApproval(Identity $approver): Decision
    {
        return $this->requirePermission(
            $approver,
            $this->settings->string('authorization.permissions.approve', 'impersonator.approve'),
            Decision::MISSING_PERMISSION,
            'You are not permitted to approve impersonation requests.',
        );
    }

    public function authorizeAuditAccess(Identity $impersonator): Decision
    {
        return $this->requirePermission(
            $impersonator,
            $this->settings->string('authorization.permissions.audit_view', 'impersonator.audit.view'),
            Decision::MISSING_PERMISSION,
            'You are not permitted to view the impersonation audit trail.',
        );
    }

    // ── Rules ───────────────────────────────────────────────────────────────

    protected function checkEnterPermission(Identity $impersonator): Decision
    {
        return $this->requirePermission(
            $impersonator,
            $this->settings->string('authorization.permissions.enter', 'impersonator.enter'),
            Decision::MISSING_PERMISSION,
            'You are not permitted to impersonate.',
        );
    }

    /**
     * Protected roles can never be impersonated.
     *
     * Checked on the target alone, with no reference to the impersonator's privileges,
     * because the point is that this is not something privilege can overcome — an
     * operator who could grant themselves any permission still cannot reach these
     * accounts through the package.
     */
    protected function checkTargetNotProtected(ImpersonationRequest $request): Decision
    {
        $protected = $this->settings->stringList('authorization.roles.protected');

        if ($protected === []) {
            return Decision::allow();
        }

        $target = $this->resolveTarget($request);

        foreach ($protected as $role) {
            if ($target !== null && $this->hasRole($target, $role)) {
                return Decision::deny(
                    Decision::PROTECTED_ROLE,
                    'That account holds a protected role and cannot be impersonated.',
                    ['role' => $role],
                );
            }
        }

        return Decision::allow();
    }

    /**
     * The hierarchy rule.
     *
     * A configured closure or invokable class wins outright — an application's own
     * notion of seniority is not something this package can guess. Otherwise the
     * built-in check compares the highest configured role level on each side and
     * requires the impersonator's to be strictly greater, so peers cannot impersonate
     * one another.
     *
     * Skipped entirely when neither side has any recognised role, since a hierarchy
     * comparison between two unranked users has no meaningful answer and denying would
     * break every install that never configured levels.
     */
    protected function checkHierarchy(ImpersonationRequest $request): Decision
    {
        $rule = $this->settings->raw('authorization.roles.hierarchy');

        if ($rule !== null) {
            return $this->applyCustomHierarchy($rule, $request);
        }

        $levels = $this->settings->array('authorization.roles.levels');

        if ($levels === []) {
            return Decision::allow();
        }

        $impersonator = $this->identities->resolveActor($request->impersonator);
        $target = $this->resolveTarget($request);

        if ($impersonator === null || $target === null) {
            return Decision::allow();
        }

        $mine = $this->highestLevel($impersonator, $levels);
        $theirs = $this->highestLevel($target, $levels);

        if ($mine === null && $theirs === null) {
            return Decision::allow();
        }

        if (($mine ?? 0) > ($theirs ?? 0)) {
            return Decision::allow();
        }

        return Decision::deny(
            Decision::HIERARCHY_VIOLATION,
            'You cannot impersonate an account at or above your own level.',
            ['detail' => 'level', 'impersonator_level' => $mine, 'target_level' => $theirs],
        );
    }

    // ── Duck-typed RBAC access ──────────────────────────────────────────────

    protected function requirePermission(
        Identity $identity,
        string $permission,
        string $code,
        string $reason,
    ): Decision {
        if ($permission === '') {
            return Decision::allow();
        }

        $user = $this->identities->resolveActor($identity);

        if ($user === null) {
            return Decision::deny($code, $reason, ['permission' => $permission]);
        }

        // No permission API at all means no opinion: the base rules already ran, and
        // requiring every user model to implement one would make an RBAC package a hard
        // dependency of this one.
        if (! method_exists($user, 'hasPermissionTo')) {
            return Decision::allow();
        }

        return $this->userHasPermission($user, $permission)
            ? Decision::allow()
            : Decision::deny($code, $reason, ['permission' => $permission]);
    }

    /**
     * `hasPermissionTo` throws rather than returning false for a permission that was
     * never registered, which would otherwise turn a missing seed row into a 500 on an
     * unrelated request. An unknown permission is treated as not held — the safe
     * reading, since the caller demonstrably does not have it.
     */
    protected function userHasPermission(Model $user, string $permission): bool
    {
        if (! method_exists($user, 'hasPermissionTo')) {
            return false;
        }

        try {
            return $user->hasPermissionTo($permission) === true;
        } catch (Throwable) {
            return false;
        }
    }

    protected function hasRole(Model $user, string $role): bool
    {
        if (! method_exists($user, 'hasRole')) {
            return false;
        }

        try {
            return $user->hasRole($role) === true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * The highest level among the user's roles, or null when they hold none that are
     * ranked.
     *
     * @param array<array-key, mixed> $levels
     */
    protected function highestLevel(Model $user, array $levels): ?int
    {
        $highest = null;

        foreach ($levels as $role => $level) {
            if (! is_numeric($level) || ! $this->hasRole($user, (string) $role)) {
                continue;
            }

            $highest = max($highest ?? 0, (int) $level);
        }

        return $highest;
    }

    /**
     * A closure or invokable class supplied by the application.
     *
     * Anything other than a clear `true` denies. A hierarchy rule that returned null,
     * a string or an exception must not read as permission — this is the one place an
     * application can widen access, so it fails closed.
     */
    protected function applyCustomHierarchy(mixed $rule, ImpersonationRequest $request): Decision
    {
        $impersonator = $this->identities->resolveActor($request->impersonator);
        $target = $this->resolveTarget($request);

        $callable = match (true) {
            $rule instanceof Closure                                                    => $rule,
            is_string($rule) && class_exists($rule) && method_exists($rule, '__invoke') => new $rule,
            is_callable($rule)                                                          => $rule,
            default                                                                     => null,
        };

        if ($callable === null) {
            return Decision::deny(
                Decision::HIERARCHY_VIOLATION,
                'The configured impersonation hierarchy rule is not callable.',
                ['detail' => 'not_callable', 'rule' => is_string($rule) ? $rule : get_debug_type($rule)],
            );
        }

        try {
            $allowed = $callable($impersonator, $target, $request);
        } catch (Throwable $e) {
            return Decision::deny(
                Decision::HIERARCHY_VIOLATION,
                'The impersonation hierarchy rule refused this impersonation.',
                ['detail' => 'rule', 'error' => $e::class],
            );
        }

        return $allowed === true
            ? Decision::allow()
            : Decision::deny(
                Decision::HIERARCHY_VIOLATION,
                'You cannot impersonate that account.',
                ['detail' => 'default'],
            );
    }
}
