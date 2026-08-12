<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Contracts;

use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;

/**
 * May this impersonation happen?
 *
 * The single gate every path goes through — HTTP, API, and the CLI enter
 * command alike. Nothing bypasses it, including token redemption: the policy is
 * re-checked when a handoff completes, because permissions can be withdrawn
 * between issuing a token and redeeming it.
 *
 * Implementations return a Decision rather than throwing, so callers can log a
 * refusal with its specific code before deciding how to surface it. Anything
 * unexpected must deny — a policy that fails open is not a policy.
 */
interface AuthorizationPolicy
{
    /**
     * The full check for entering: identity rules (no self-impersonation, no
     * nesting, target not soft-deleted), the target class allowlist, the model
     * hooks, the `impersonate` gate ability, RBAC permissions and protected
     * roles, hierarchy, a required reason, and the concurrency caps.
     */
    public function authorize(ImpersonationRequest $request): Decision;

    /**
     * Whether this operator may use this mode at all, checked independently of
     * a specific target so a UI can offer only the modes the operator holds.
     *
     * With spatie/laravel-permission installed this maps to the per-mode
     * permission, which is what lets junior support staff be pinned to
     * `read_only` while a senior operator may choose `full`.
     */
    public function authorizeMode(Identity $impersonator, string $mode): Decision;

    /**
     * Whether this operator may end an impersonation they do not own — the kill
     * switch. Distinct from `authorize` because revoking is a de-escalation and
     * warrants its own permission.
     */
    public function authorizeRevoke(Identity $impersonator, string $auditId): Decision;

    /**
     * Whether this operator may decide somebody else's break-glass request.
     *
     * Its own permission, separate from `enter`: authorising access and using it are
     * different roles, and an install where one permission covered both would have no
     * four-eyes control — the same operator could raise a request and wave it through.
     *
     * Note this says nothing about *which* request. That the approver is not also the
     * requester is checked against the specific row, since it is a property of the pair
     * rather than of the operator.
     */
    public function authorizeApproval(Identity $approver): Decision;

    /** Whether this operator may read the audit trail. */
    public function authorizeAuditAccess(Identity $impersonator): Decision;
}
