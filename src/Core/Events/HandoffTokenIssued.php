<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * A single-use cross-domain handoff token was minted.
 *
 * Carries no token value, by construction — the plaintext exists only in the accept
 * URL handed to the caller, and an event is serialised into queues and logs, which
 * is precisely where it must never appear. Correlate through `session->auditId`.
 */
final readonly class HandoffTokenIssued
{
    public function __construct(public ImpersonationSession $session) {}
}
