<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Authorization;

use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Impersonator\Core\Support\ModeRegistry;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Laravel\Support\SessionState;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * The always-on authorization rules — the checks that apply whether or not an
 * RBAC package is installed.
 *
 * Every path into impersonation passes through here: HTTP, the REST API, and the
 * CLI enter command. Token redemption re-runs it rather than trusting the decision
 * made when the token was minted, because a role can change or a row can be
 * revoked in the seconds between issuing a link and following it.
 *
 * Two design rules hold throughout:
 *
 *  - **Order is cheapest-first.** The identity rules need no queries, so a
 *    self-impersonation attempt is refused without touching the database.
 *  - **Anything unexpected denies.** A policy that fails open is not a policy, so
 *    an unresolvable target or an unreadable config produces a denial rather than
 *    an exception that some caller might catch and continue past.
 */
class BasePolicy implements AuthorizationPolicy
{
    /**
     * Memoised per request: several rules need the target, and it is one query.
     *
     * @var array<string, Model|null>
     */
    protected array $resolvedTargets = [];

    public function __construct(
        protected Gate $gate,
        protected AuditStore $audits,
        protected IdentityResolver $identities,
        protected ModeRegistry $modes,
        protected SessionState $state,
        protected Settings $settings,
        // The raw session, for the step-up timestamp. SessionState wraps only this package's own key,
        // and the confirmation stamp belongs to Laravel's `password.confirm` flow rather than to us.
        protected Session $session,
    ) {}

    public function authorize(ImpersonationRequest $request): Decision
    {
        return Decision::all([
            fn (): Decision => $this->checkEnabled(),
            fn (): Decision => $this->checkNotSelf($request),
            fn (): Decision => $this->checkNotNested(),
            fn (): Decision => $this->checkReason($request),
            fn (): Decision => $this->checkModeRegistered($request),
            fn (): Decision => $this->authorizeMode($request->impersonator, $request->mode->name),
            fn (): Decision => $this->checkStepUp($request),
            fn (): Decision => $this->checkTargetAllowlisted($request),
            fn (): Decision => $this->checkParticipantsResolve($request),
            fn (): Decision => $this->checkTargetNotTrashed($request),
            fn (): Decision => $this->checkModelHooks($request),
            fn (): Decision => $this->checkTargetEligible($request),
            fn (): Decision => $this->checkGate($request),
            fn (): Decision => $this->checkConcurrency($request),
        ]);
    }

    /**
     * The base policy has no notion of per-mode permission — that arrives with
     * spatie/laravel-permission. Registration was already verified upstream, so
     * an operator may use any registered mode here.
     */
    public function authorizeMode(Identity $impersonator, string $mode): Decision
    {
        return $this->modes->has($mode)
            ? Decision::allow()
            : Decision::deny(
                Decision::MISSING_MODE_PERMISSION,
                sprintf('Impersonation mode [%s] is not registered.', $mode),
                ['mode' => $mode],
            );
    }

    /**
     * The base policy has no revoke permission — that arrives with the RBAC layer.
     *
     * Note this deliberately does not consult the master switch: turning
     * impersonation off during an incident must not also remove the ability to kill
     * the sessions already running.
     */
    public function authorizeRevoke(Identity $impersonator, string $auditId): Decision
    {
        return Decision::allow();
    }

    /**
     * The base policy has no approve permission — that arrives with the RBAC layer.
     *
     * Note what this does *not* weaken: the requester-is-not-the-approver rule is checked
     * against the specific request rather than here, so even with no RBAC package installed
     * nobody can wave their own request through.
     */
    public function authorizeApproval(Identity $approver): Decision
    {
        return Decision::allow();
    }

    public function authorizeAuditAccess(Identity $impersonator): Decision
    {
        return Decision::allow();
    }

    // ── Individual rules ────────────────────────────────────────────────────

    protected function checkEnabled(): Decision
    {
        return $this->settings->bool('enabled', true)
            ? Decision::allow()
            : Decision::deny(Decision::DISABLED, 'Impersonation is disabled for this application.');
    }

    protected function checkNotSelf(ImpersonationRequest $request): Decision
    {
        return $request->isSelfImpersonation()
            ? Decision::deny(Decision::SELF_IMPERSONATION, 'You cannot impersonate yourself.')
            : Decision::allow();
    }

    /**
     * Nesting is refused by default: once an impersonated session can reach a
     * third account, the audit trail stops describing who actually acted.
     */
    protected function checkNotNested(): Decision
    {
        if ($this->settings->bool('authorization.allow_nested', false)) {
            return Decision::allow();
        }

        return $this->currentlyImpersonating()
            ? Decision::deny(
                Decision::NESTED_IMPERSONATION,
                'You are already impersonating. Leave the current impersonation first.',
            )
            : Decision::allow();
    }

    protected function checkReason(ImpersonationRequest $request): Decision
    {
        if (! $this->settings->bool('reason.require', false)) {
            return Decision::allow();
        }

        if (! $request->hasReason()) {
            return Decision::deny(
                Decision::REASON_REQUIRED,
                'A reason is required to impersonate.',
                ['detail' => 'missing'],
            );
        }

        $length = mb_strlen(trim((string) $request->reason));
        $min = $this->settings->int('reason.min_length', 3);
        $max = $this->settings->int('reason.max_length', 500);

        if ($length < $min || $length > $max) {
            return Decision::deny(
                Decision::REASON_REQUIRED,
                sprintf('The reason must be between %d and %d characters.', $min, $max),
                // `min` and `max` join the context so a translation can interpolate them. The
                // English literal builds them with sprintf, which a lang line cannot reach into.
                ['detail' => 'length', 'length' => $length, 'min' => $min, 'max' => $max],
            );
        }

        return Decision::allow();
    }

    protected function checkModeRegistered(ImpersonationRequest $request): Decision
    {
        return $this->modes->has($request->mode->name)
            ? Decision::allow()
            : Decision::deny(
                Decision::MISSING_MODE_PERMISSION,
                sprintf('Impersonation mode [%s] is not registered.', $request->mode->name),
                ['mode' => $request->mode->name],
            );
    }

    /**
     * Whether the operator re-authenticated recently enough to enter.
     *
     * The strongest operator-side control available, and the one GitLab's Admin Mode exists to
     * provide: re-authenticate, then a bounded window. ASVS 7.5.3 treats entering impersonation as a
     * highly sensitive operation, and a stolen session cookie is otherwise enough to reach every
     * account in the system.
     *
     * **Off by default**, because it needs a host-side flow — Laravel's own `password.confirm` route
     * stamps `auth.password_confirmed_at`, which is what this reads. Turning it on without that flow
     * would refuse every impersonation.
     *
     * Refuses on an absent *or* stale timestamp. Absent is the more important half: treating "never
     * confirmed" as "confirmed long ago" would be the same value, but treating it as *passing* is the
     * mistake, and a missing key is exactly what an install that forgot the flow produces.
     */
    protected function checkStepUp(ImpersonationRequest $request): Decision
    {
        if (! $this->settings->bool('authorization.step_up.require', false)) {
            return Decision::allow();
        }

        $within = max(1, $this->settings->int('authorization.step_up.within', 900));
        $confirmedAt = $this->session->get(
            $this->settings->string('authorization.step_up.session_key', 'auth.password_confirmed_at'),
        );

        if (! is_numeric($confirmedAt)) {
            return Decision::deny(
                Decision::STEP_UP_REQUIRED,
                'Confirm your password before impersonating.',
                ['detail' => 'missing'],
            );
        }

        $age = time() - (int) $confirmedAt;

        return $age <= $within
            ? Decision::allow()
            : Decision::deny(
                Decision::STEP_UP_REQUIRED,
                'Confirm your password before impersonating.',
                ['detail' => 'stale', 'age_seconds' => $age, 'within_seconds' => $within],
            );
    }

    /**
     * An application's own per-instance rule about the target.
     *
     * The allowlist answers *which models*; soft deletes are the only per-row rule this package knows.
     * GitLab additionally refuses blocked, password-expired, internal and bot accounts — states this
     * package cannot know about, so this is the hook that expresses them.
     *
     * **Fails closed** on anything but a literal `true`, matching every other extension point here: a
     * rule that errors is not consent, and the whole reason to register one is that the package cannot
     * judge the condition itself.
     */
    protected function checkTargetEligible(ImpersonationRequest $request): Decision
    {
        $rule = $this->settings->raw('targets.eligibility');

        if ($rule === null) {
            return Decision::allow();
        }

        $target = $this->resolveTarget($request);

        if ($target === null) {
            // Unresolvable is already reported by checkParticipantsResolve; nothing to add.
            return Decision::allow();
        }

        try {
            $allowed = $this->callEligibility($rule, $target, $request);
        } catch (\Throwable) {
            return Decision::deny(
                Decision::TARGET_NOT_ELIGIBLE,
                'That account cannot be impersonated right now.',
                ['detail' => 'error'],
            );
        }

        return $allowed === true
            ? Decision::allow()
            : Decision::deny(
                Decision::TARGET_NOT_ELIGIBLE,
                'That account cannot be impersonated right now.',
                ['detail' => 'rule'],
            );
    }

    /**
     * Invoke the configured eligibility rule, whatever shape it was given in.
     *
     * A closure, or the name of an invokable class resolved through the container so the rule can
     * declare its own dependencies. Anything else returns false rather than being coerced: a config
     * value that is neither is a misconfiguration, and guessing at it would fail *open*.
     */
    private function callEligibility(mixed $rule, Model $target, ImpersonationRequest $request): mixed
    {
        if (is_callable($rule)) {
            return $rule($target, $request);
        }

        if (is_string($rule) && $rule !== '') {
            $resolved = app($rule);

            return is_callable($resolved) ? $resolved($target, $request) : false;
        }

        return false;
    }

    /**
     * The control that stops arbitrary class injection. Checked before the target
     * is loaded, so a caller naming any Eloquent model never gets it queried.
     */
    protected function checkTargetAllowlisted(ImpersonationRequest $request): Decision
    {
        return $this->identities->isAllowlisted($request->target->type)
            ? Decision::allow()
            : Decision::deny(
                Decision::TARGET_NOT_ALLOWLISTED,
                'That target type cannot be impersonated.',
                ['detail' => 'type', 'type' => $request->target->type],
            );
    }

    protected function checkParticipantsResolve(ImpersonationRequest $request): Decision
    {
        if ($this->resolveTarget($request) === null) {
            return Decision::deny(
                Decision::TARGET_NOT_ALLOWLISTED,
                'The impersonation target could not be found.',
                ['detail' => 'missing', 'target' => $request->target->key()],
            );
        }

        if ($this->identities->resolveActor($request->impersonator) === null) {
            return Decision::deny(
                Decision::IMPERSONATOR_NOT_PERMITTED,
                'The impersonator could not be resolved.',
                ['detail' => 'unresolved', 'impersonator' => $request->impersonator->key()],
            );
        }

        return Decision::allow();
    }

    protected function checkTargetNotTrashed(ImpersonationRequest $request): Decision
    {
        if ($this->settings->bool('targets.allow_soft_deleted', false)) {
            return Decision::allow();
        }

        $target = $this->resolveTarget($request);

        return $target !== null && $this->identities->isTrashed($target)
            ? Decision::deny(
                Decision::TARGET_SOFT_DELETED,
                'That account has been deleted and cannot be impersonated.',
            )
            : Decision::allow();
    }

    /**
     * The `canImpersonate()` / `canBeImpersonated()` model hooks.
     *
     * Absent methods mean "no opinion" rather than "no": requiring every model to
     * implement both would make the trait mandatory, and the hooks are meant to be
     * an override, not a gate everyone must pass through.
     */
    protected function checkModelHooks(ImpersonationRequest $request): Decision
    {
        $impersonator = $this->identities->resolveActor($request->impersonator);

        if ($impersonator !== null
            && method_exists($impersonator, 'canImpersonate')
            && $impersonator->canImpersonate() !== true) {
            return Decision::deny(
                Decision::IMPERSONATOR_NOT_PERMITTED,
                'You are not permitted to impersonate.',
                ['detail' => 'default'],
            );
        }

        $target = $this->resolveTarget($request);

        if ($target !== null
            && method_exists($target, 'canBeImpersonated')
            && $target->canBeImpersonated() !== true) {
            return Decision::deny(
                Decision::TARGET_OPTED_OUT,
                'That account cannot be impersonated.',
            );
        }

        return Decision::allow();
    }

    /**
     * The `impersonate` gate ability, consulted only when the application defined
     * one. An undefined ability denies everything in Laravel, so treating "not
     * defined" as "denied" would break every install that never opted in.
     */
    protected function checkGate(ImpersonationRequest $request): Decision
    {
        $ability = $this->settings->nullableString('authorization.gate_ability');

        if ($ability === null || ! $this->gate->has($ability)) {
            return Decision::allow();
        }

        $impersonator = $this->identities->resolveActor($request->impersonator);
        $target = $this->resolveTarget($request);

        if ($impersonator === null || $target === null) {
            return Decision::deny(
                Decision::GATE_DENIED,
                'The impersonation participants could not be resolved for the gate check.',
                ['detail' => 'unresolved'],
            );
        }

        return $this->gate->forUser($impersonator)->allows($ability, $target)
            ? Decision::allow()
            : Decision::deny(
                Decision::GATE_DENIED,
                'You are not authorized to impersonate that account.',
                ['detail' => 'default'],
            );
    }

    /**
     * The concurrency caps.
     *
     * Advisory at this layer: the authoritative enforcement is a locked
     * transaction in the audit store, because a count read here and an insert
     * performed later is a race two simultaneous requests can both win. Checking
     * here still gives the caller a clear refusal instead of a lock timeout.
     */
    protected function checkConcurrency(ImpersonationRequest $request): Decision
    {
        $max = $this->settings->positiveIntOrNull('limits.max_active_per_impersonator');

        if ($max !== null) {
            $active = $this->audits->countActiveFor($request->impersonator);

            if ($active >= $max) {
                return Decision::deny(
                    Decision::CONCURRENCY_LIMIT,
                    sprintf('You are at your limit of %d concurrent impersonations.', $active),
                    ['count' => $active, 'active' => $active, 'max' => $max],
                );
            }
        }

        if ($this->settings->bool('limits.deny_when_target_busy', false)) {
            foreach ($this->audits->activeTargeting($request->target) as $existing) {
                if ($existing->impersonator->isNot($request->impersonator)) {
                    return Decision::deny(
                        Decision::TARGET_BUSY,
                        'Somebody else is already impersonating that account.',
                        ['audit_id' => $existing->auditId],
                    );
                }
            }
        }

        return Decision::allow();
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /**
     * The target, loaded once per request.
     *
     * Loaded `withTrashed` so a soft-deleted account is found and then refused by
     * name. Excluding it here instead would surface as "target not found", which
     * tells an operator to go looking for a missing record rather than that the
     * account was deleted.
     */
    protected function resolveTarget(ImpersonationRequest $request): ?Model
    {
        return $this->resolvedTargets[$request->target->key()] ??= $this->identities->toUser(
            $request->target,
            withTrashed: true,
        );
    }

    /**
     * Whether the caller is already inside an impersonation.
     *
     * Read from session state rather than from the manager: the manager builds
     * drivers, a driver needs the policy, and having the policy require the manager
     * back would close that loop at construction time.
     */
    protected function currentlyImpersonating(): bool
    {
        return $this->state->has();
    }
}
