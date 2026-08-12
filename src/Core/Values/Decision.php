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
