<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Throwable;
use Traversable;

/**
 * What roles a reviewer holds, and whether they may decide a particular request.
 *
 * Extracted rather than duplicated: `RbacPolicy` already asks a model for its roles through the same
 * duck-typed surface, wrapped in the same `try`/`catch` — spatie's `hasRole()` throws on an unknown
 * role rather than returning false, so an unguarded call turns a typo in a config file into a 500 on
 * an approval screen. One copy of that knowledge, not two.
 *
 * **Duck-typed on purpose.** `hasRole()` and `getRoleNames()` are spatie's shape but also several
 * other packages', so this needs no dependency and no `class_exists` probe. A model exposing neither
 * simply has no roles, which makes a role-based policy unsatisfiable — correctly, and visibly,
 * rather than by accident.
 *
 * Everything here **fails closed**: a missing method, a throw, or a non-`true` answer all mean "no".
 */
final class ReviewerDirectory
{
    /** An application-supplied rule config cannot express. */
    private ?Closure $eligibility = null;

    public function __construct(private readonly Settings $settings) {}

    /**
     * Register a per-request eligibility rule.
     *
     * This is what expresses *"must be the requester's line manager"* — a relationship this package
     * has no business modelling. Registered at runtime because it is a closure over the host's own
     * domain.
     *
     * @param Closure(Model, ApprovalRequest): mixed $rule
     */
    public function eligibilityUsing(Closure $rule): self
    {
        $this->eligibility = $rule;

        return $this;
    }

    /**
     * The roles this reviewer holds, of the ones a policy asks about.
     *
     * Narrowed to the policy's own slots rather than enumerating everything the model holds. Two
     * reasons: `getRoleNames()` may be absent while `hasRole()` is present, and asking only about the
     * roles that matter avoids pulling a full role list to answer a question about two of them.
     *
     * @param list<string> $roles
     * @return list<string>
     */
    public function rolesFor(Model $reviewer, array $roles): array
    {
        return array_values(array_filter(
            $roles,
            fn (string $role): bool => $this->hasRole($reviewer, $role),
        ));
    }

    /**
     * Whether a model holds a role.
     *
     * The `try`/`catch` is load-bearing, not defensive habit: spatie's `hasRole()` raises
     * `RoleDoesNotExist` for a role nobody has created, so a policy naming `auditor` before anyone
     * seeded it would otherwise 500 the approval screen rather than reporting the slot unfilled.
     */
    public function hasRole(Model $reviewer, string $role): bool
    {
        if (! method_exists($reviewer, 'hasRole')) {
            return false;
        }

        try {
            return $reviewer->hasRole($role) === true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Every role name the model reports, when it can report them.
     *
     * For a UI listing what a reviewer could sign off as. Not used for the decision itself, which
     * goes through {@see rolesFor()} against the policy's slots.
     *
     * @return list<string>
     */
    public function allRolesOf(Model $reviewer): array
    {
        if (! method_exists($reviewer, 'getRoleNames')) {
            return [];
        }

        try {
            $names = $reviewer->getRoleNames();
        } catch (Throwable) {
            return [];
        }

        $roles = [];

        foreach ($names instanceof Traversable ? iterator_to_array($names) : (array) $names as $name) {
            if (is_string($name) && $name !== '') {
                $roles[] = $name;
            }
        }

        return array_values(array_unique($roles));
    }

    /**
     * Whether the application's own rule permits this reviewer to decide this request.
     *
     * True when no rule is configured — this is an additional restriction, not a gate every install
     * has to satisfy.
     *
     * **Anything other than a literal `true` denies**, including a truthy string and a thrown
     * exception. A rule that errors must not be read as "yes": the whole point of registering one is
     * that the package cannot judge the relationship itself, so its silence is not consent.
     */
    public function isEligible(Model $reviewer, ApprovalRequest $request): bool
    {
        $rule = $this->eligibility ?? $this->configuredRule();

        if ($rule === null) {
            return true;
        }

        try {
            return $rule($reviewer, $request) === true;
        } catch (Throwable) {
            return false;
        }
    }

    public function hasEligibilityRule(): bool
    {
        return $this->eligibility !== null || $this->configuredRule() !== null;
    }

    /**
     * A rule named in config, as `Class@method`, `[Class, 'method']` or an invokable class name.
     *
     * Resolved through the container so the rule can take its own dependencies — a line-manager check
     * usually needs a repository.
     */
    private function configuredRule(): ?Closure
    {
        $configured = $this->settings->raw('approval.eligibility');

        if ($configured instanceof Closure) {
            return $configured;
        }

        if (is_string($configured) && $configured !== '') {
            return static function (Model $reviewer, ApprovalRequest $request) use ($configured): mixed {
                if (str_contains($configured, '@')) {
                    [$class, $method] = explode('@', $configured, 2);
                    $instance = app($class);

                    // Verified rather than assumed. A config naming a class that has no such method —
                    // a rename, a typo — would otherwise be a fatal error on an approval screen; false
                    // instead means the rule refuses, which is the fail-closed reading.
                    return is_object($instance) && method_exists($instance, $method)
                        ? $instance->{$method}($reviewer, $request)
                        : false;
                }

                $invokable = app($configured);

                return is_callable($invokable) ? $invokable($reviewer, $request) : false;
            };
        }

        return null;
    }
}
