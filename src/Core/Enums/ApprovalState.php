<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Enums;

use Simtabi\Laranail\Enumerator\Attributes\Label;
use Simtabi\Laranail\Enumerator\Concerns\HasAttributes;
use Simtabi\Laranail\Enumerator\Concerns\IsTranslatable;
use Simtabi\Laranail\Enumerator\Contracts\Translatable;

/**
 * Where a break-glass approval request stands.
 *
 * Persisted in `impersonator_approval_requests.state`. `Approved` and `Consumed` are
 * deliberately separate: an approval is a **one-time permit**, so "a second operator said
 * yes" and "that yes has been spent" are different facts. Collapsing them would make a
 * granted approval reusable, which turns one approval into unlimited access to that
 * account for as long as the row survives.
 *
 * The `value` is the contract; the label is not. Values are persisted in `state`, returned by the
 * API and matched in logs, so they are never translated — `label()` exists for display only.
 */
enum ApprovalState: string implements Translatable
{
    use HasAttributes;
    use IsTranslatable;

    /** Waiting on a second operator. Nobody is impersonating anything. */
    #[Label('Awaiting approval')]
    case Pending = 'pending';

    /**
     * At least one reviewer approved, and the chain still needs more.
     *
     * Distinct from `Pending` because the two answer different questions for an approver looking at a
     * queue: nobody has looked at this yet, versus somebody has and it is short of quorum. Both are
     * open, and `consume()` refuses both — a partially approved request is not a permit.
     */
    #[Label('Partially approved')]
    case PartiallyApproved = 'partially_approved';

    /** Approved and not yet used. The requester may now enter, once. */
    #[Label('Approved')]
    case Approved = 'approved';

    /** Spent. The impersonation it authorised has begun. */
    #[Label('Used')]
    case Consumed = 'consumed';

    /** A second operator refused it. */
    #[Label('Denied')]
    case Denied = 'denied';

    /** Nobody answered before the TTL elapsed. */
    #[Label('Expired')]
    case Expired = 'expired';

    /**
     * Whether this state can still become an impersonation.
     *
     * `PartiallyApproved` is included, and omitting it would be the dangerous mistake: a chain short
     * of quorum would read as closed, so the sweeper would expire it out from under reviewers who were
     * still working through it, and a queue filtered on "open" would hide it from the very people it
     * is waiting on.
     */
    public function isOpen(): bool
    {
        return in_array($this, [self::Pending, self::PartiallyApproved, self::Approved], true);
    }

    /**
     * Whether a final decision has been recorded, by a person or by the clock.
     *
     * A partially approved chain is **not** decided. Reviewers have spoken but the request has not
     * been answered, and treating it as answered is what would let a single approval on a two-reviewer
     * policy behave like a permit.
     */
    public function isDecided(): bool
    {
        return $this !== self::Pending && $this !== self::PartiallyApproved;
    }

    /** Whether reviewers may still add a decision to this request. */
    public function acceptsDecisions(): bool
    {
        return $this === self::Pending || $this === self::PartiallyApproved;
    }

    /**
     * Pinned rather than derived. `IsTranslatable::translationSlug()` defaults to
     * `class_basename()`, a Laravel helper called without a `function_exists()` guard — the only
     * unguarded one in that trait. Overriding it keeps this enum usable outside a booted
     * application, and stops a class rename silently relocating every translation key.
     */
    public static function translationSlug(): string
    {
        return 'approval_state';
    }

    public static function translationNamespace(): string
    {
        return 'laranail-impersonator';
    }
}
