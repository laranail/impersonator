<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

/**
 * A handoff token was presented and refused.
 *
 * `reason` is the internal distinction — unknown, expired, already_used, revoked —
 * which the client never sees, because telling an attacker probing the accept route
 * whether a token merely expired is telling them the token was real.
 *
 * A replayed token reaching here is the signal worth alerting on.
 */
final readonly class HandoffTokenRejected
{
    public function __construct(
        public string $reason,
        public ?string $ip = null,
    ) {}
}
