<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/**
 * Answers "who really did this" for activity-log packages.
 *
 * This is the correctness fix that nothing else in this space ships. During an
 * impersonation `auth()->user()` is the *target*, so any package that resolves a causer
 * from the auth context records the customer as having done what the support engineer
 * did. The audit trail then says the customer changed their own plan, cancelled their
 * own order, deleted their own account — and the one fact that actually matters, that
 * an operator was inside the account, is nowhere in it.
 *
 * Three strategies:
 *
 *  - `impersonator` — the operator is the causer. Correct, and the default.
 *  - `target` — legacy behaviour, for a report that already depends on it.
 *  - `both` — operator as causer, target recorded alongside, for teams that want the
 *    subject visible in the same row.
 *
 * Outside an impersonation this always resolves to the authenticated user, so it is
 * safe to register unconditionally.
 */
final readonly class CauserResolver
{
    public const string IMPERSONATOR = 'impersonator';

    public const string TARGET = 'target';

    public const string BOTH = 'both';

    public function __construct(
        private ImpersonationManager $impersonator,
        private Settings $settings,
    ) {}

    /** The model that should be recorded as having performed the current action. */
    public function causer(): Authenticatable|Model|null
    {
        $session = $this->impersonator->current();

        if ($session === null) {
            return $this->impersonator->currentImpersonatorOrNull();
        }

        return match ($this->strategy()) {
            self::TARGET => $this->impersonator->target() ?? $this->impersonator->actor(),
            default => $this->impersonator->actor(),
        };
    }

    /**
     * Extra properties to attach to a logged activity, so an impersonated action is
     * identifiable as one after the fact.
     *
     * Always includes the audit id, whatever the strategy: a log entry that records the
     * operator but not *which* impersonation is far harder to reconcile against the
     * trail than one carrying the correlation id.
     *
     * @return array<string, mixed>
     */
    public function properties(): array
    {
        $session = $this->impersonator->current();

        if ($session === null) {
            return [];
        }

        $properties = [
            'impersonated' => true,
            'impersonation_audit_id' => $session->auditId,
            'impersonation_mode' => $session->mode->name,
        ];

        if ($this->strategy() === self::BOTH) {
            $key = $this->settings->string('causer.property_key', 'impersonated_target');

            $properties[$key] = $session->target->toArray();
            $properties['impersonated_by'] = $session->impersonator->toArray();
        }

        return $properties;
    }

    public function isImpersonating(): bool
    {
        return $this->impersonator->isImpersonating();
    }

    /**
     * An unrecognised strategy falls back to `impersonator` rather than erroring: this
     * runs inside somebody else's logging pipeline, and a typo in config must not take
     * down every write in the application.
     */
    public function strategy(): string
    {
        return $this->settings->enum(
            'causer.strategy',
            [self::IMPERSONATOR, self::TARGET, self::BOTH],
            self::IMPERSONATOR,
        );
    }
}
