<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Policies;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Auth\Authenticatable;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;

/**
 * The Laravel policy for audit rows, so `$user->can('view', $audit)` works and Blade's
 * `@can` directive covers the audit UI.
 *
 * Every method delegates to the single AuthorizationPolicy rather than deciding anything. That
 * indirection is the point: a policy that reimplemented the permission checks would be a second
 * set of rules to keep in sync with the API, the console and the middleware — and the copy is
 * always the one that drifts.
 *
 * There is deliberately no `create`, `update` or `delete`. Audit rows are append-only from the
 * package's perspective; the only writes are the terminal transitions, and those are performed by
 * the package itself rather than authorized per-user. Retention pruning is a scheduled sweep, not
 * a user action.
 */
final readonly class ImpersonationAuditPolicy
{
    public function __construct(
        private AuthorizationPolicy $policy,
        private IdentityResolver $identities,
    ) {}

    public function viewAny(Authenticatable|Model $user): bool
    {
        return $this->policy->authorizeAuditAccess($this->identities->fromUser($user))->allowed;
    }

    public function view(Authenticatable|Model $user): bool
    {
        return $this->viewAny($user);
    }

    /** Exporting is reading, so it is gated by the same permission. */
    public function export(Authenticatable|Model $user): bool
    {
        return $this->viewAny($user);
    }

    /**
     * Revoking is a separate permission from reading.
     *
     * An auditor who may read every impersonation has no business ending one, and an operator who
     * may end one does not thereby gain the whole trail.
     */
    public function revoke(Authenticatable|Model $user, ImpersonationAudit $audit): bool
    {
        $key = $audit->getKey();

        return $this->policy->authorizeRevoke(
            $this->identities->fromUser($user),
            is_scalar($key) ? (string) $key : '',
        )->allowed;
    }
}
