<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

/**
 * The outcome of an authorization check.
 *
 * Deliberately not a bare bool. Every denial carries a stable machine-readable
 * `code` and a human `reason`, because "impersonation was refused" is a
 * security event that has to be greppable in a log six months later. The codes
 * below are the closed set the built-in policy emits; custom policies may add
 * their own.
 */
final readonly class Decision
{
    public const string SELF_IMPERSONATION = 'self_impersonation';

    public const string NESTED_IMPERSONATION = 'nested_impersonation';

    public const string TARGET_SOFT_DELETED = 'target_soft_deleted';

    public const string TARGET_NOT_ALLOWLISTED = 'target_not_allowlisted';

    public const string TARGET_OPTED_OUT = 'target_opted_out';

    public const string IMPERSONATOR_NOT_PERMITTED = 'impersonator_not_permitted';

    public const string MISSING_PERMISSION = 'missing_permission';

    public const string MISSING_MODE_PERMISSION = 'missing_mode_permission';

    public const string PROTECTED_ROLE = 'protected_role';

    public const string HIERARCHY_VIOLATION = 'hierarchy_violation';

    public const string GATE_DENIED = 'gate_denied';

    public const string REASON_REQUIRED = 'reason_required';

    public const string RATE_LIMITED = 'rate_limited';

    public const string CONCURRENCY_LIMIT = 'concurrency_limit';

    public const string TARGET_BUSY = 'target_busy';

    public const string APPROVAL_REQUIRED = 'approval_required';

    public const string DISABLED = 'disabled';

    /** The active mode refused the action, rather than the target lacking permission. */
    public const string MODE_FORBIDS_WRITE = 'mode_forbids_write';

    /** The impersonation was revoked or outlived max_duration and must terminate. */
    public const string SESSION_TERMINATED = 'session_terminated';

    /**
     * The reviewer may not decide *this* request, though they hold the approve permission.
     *
     * Either they fill no outstanding role slot, or the application's own eligibility rule refused.
     * Distinct from `missing_permission`, which is about the operator in general — sending somebody to
     * ask for a permission they already hold is how a control gets configured away.
     */
    public const string APPROVER_NOT_ELIGIBLE = 'approver_not_eligible';

    /**
     * The operator has not re-authenticated recently enough.
     *
     * Distinct from `missing_permission`: they hold every right, they simply have not proved they are
     * still at the keyboard. Telling them they lack permission would send them asking for access they
     * already have.
     */
    public const string STEP_UP_REQUIRED = 'step_up_required';

    /** The target is not eligible right now — blocked, suspended, whatever the application decides. */
    public const string TARGET_NOT_ELIGIBLE = 'target_not_eligible';

    /** The impersonation sat idle past `limits.max_idle`. */
    public const string SESSION_IDLE = 'session_idle';

    /** Nothing to act on: the caller asked about an impersonation that is not running. */
    public const string NOT_IMPERSONATING = 'not_impersonating';

    /** Extensions are switched off, so this impersonation runs for its original window only. */
    public const string EXTENSION_DISABLED = 'extension_disabled';

    /** `limits.extension.max` extensions have already been granted. */
    public const string EXTENSION_LIMIT = 'extension_limit';

    /**
     * Granting more time would pass `limits.extension.max_total_duration`.
     *
     * The ceiling that makes a short `max_duration` mean something: without it, unlimited
     * extensions turn a ten-minute window into an open-ended one a minute at a time.
     */
    public const string EXTENSION_CEILING = 'extension_ceiling';

    /** Outside the `limits.extension.within` window — there is still time left to use. */
    public const string EXTENSION_TOO_EARLY = 'extension_too_early';

    /** @param array<string, mixed> $context */
    private function __construct(
        public bool $allowed,
        public ?string $code = null,
        public ?string $reason = null,
        public array $context = [],
    ) {}

    public static function allow(): self
    {
        return new self(true);
    }

    /** @param array<string, mixed> $context */
    public static function deny(string $code, string $reason, array $context = []): self
    {
        return new self(false, $code, $reason, $context);
    }

    public function denied(): bool
    {
        return ! $this->allowed;
    }

    /**
     * Short-circuiting conjunction: the first denial wins and is returned
     * intact, so the caller always learns the specific rule that refused.
     *
     * @param iterable<callable(): self> $checks
     */
    public static function all(iterable $checks): self
    {
        foreach ($checks as $check) {
            $decision = $check();

            if ($decision->denied()) {
                return $decision;
            }
        }

        return self::allow();
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'code' => $this->code,
            'reason' => $this->reason,
            'context' => $this->context,
        ];
    }
}
