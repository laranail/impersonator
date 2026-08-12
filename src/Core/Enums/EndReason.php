<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Enums;

/**
 * Why an impersonation stopped. A genuinely closed set, so unlike Mode this is
 * a real enum. Persisted in `impersonator_audits.ended_by`.
 */
enum EndReason: string
{
    /** The impersonator explicitly left, or the target session logged out. */
    case Left = 'left';

    /** max_duration elapsed, or the issued credential outlived its TTL. */
    case Expired = 'expired';

    /** An administrator killed it remotely through the revocation switch. */
    case Revoked = 'revoked';

    /**
     * The session backing the impersonation vanished without a leave — the
     * cookie was dropped, the session store was flushed, or the process died.
     * Recorded on the next reconciliation rather than left dangling as active,
     * because a row that is open forever reads as an ongoing breach.
     */
    case SessionLost = 'session_lost';

    /** Whether the impersonation was ended by someone other than its owner. */
    public function isInvoluntary(): bool
    {
        return $this !== self::Left;
    }

    public function label(): string
    {
        return match ($this) {
            self::Left => 'Left',
            self::Expired => 'Expired',
            self::Revoked => 'Revoked',
            self::SessionLost => 'Session lost',
        };
    }
}
