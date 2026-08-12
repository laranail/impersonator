<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Enums;

/**
 * Where a break-glass approval request stands.
 *
 * Persisted in `impersonator_approval_requests.state`. `Approved` and `Consumed` are
 * deliberately separate: an approval is a **one-time permit**, so "a second operator said
 * yes" and "that yes has been spent" are different facts. Collapsing them would make a
 * granted approval reusable, which turns one approval into unlimited access to that
 * account for as long as the row survives.
 */
enum ApprovalState: string
{
    /** Waiting on a second operator. Nobody is impersonating anything. */
    case Pending = 'pending';

    /** Approved and not yet used. The requester may now enter, once. */
    case Approved = 'approved';

    /** Spent. The impersonation it authorised has begun. */
    case Consumed = 'consumed';

    /** A second operator refused it. */
    case Denied = 'denied';

    /** Nobody answered before the TTL elapsed. */
    case Expired = 'expired';

    /** Whether this state can still become an impersonation. */
    public function isOpen(): bool
    {
        return $this === self::Pending || $this === self::Approved;
    }

    /** Whether a decision has been recorded, by a person or by the clock. */
    public function isDecided(): bool
    {
        return $this !== self::Pending;
    }

    public function label(): string
    {
        return match ($this) {
            self::Pending => 'Awaiting approval',
            self::Approved => 'Approved',
            self::Consumed => 'Used',
            self::Denied => 'Denied',
            self::Expired => 'Expired',
        };
    }
}
