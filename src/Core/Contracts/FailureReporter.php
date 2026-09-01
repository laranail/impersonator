<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Contracts;

use Throwable;

/**
 * Routes a handled failure to the central error handler — logs *and* monitoring.
 *
 * A contract rather than a direct call to a framework helper because the Core layer
 * has to stay framework-free, and because tests need a fake reporter to assert what
 * was reported without reaching live monitoring.
 *
 * Implementations must be guarded internally: a broken monitoring integration is
 * itself the reporting substrate, and it must never escalate a degradable failure
 * into a crash. It falls back to a last-resort local write instead.
 */
interface FailureReporter
{
    /** Report a handled failure. Must never throw. */
    public function report(Throwable $failure): void;

    /**
     * Log a suspicious-but-non-fatal condition: a fallback that fired, a value out
     * of expected range that was tolerated, an invariant that only just held.
     *
     * Separate from `report()` because severity has to match reality — a tolerated
     * anomaly and a real failure must not log at the same level. These are early
     * signal; losing them means finding out only when something finally throws.
     *
     * @param  array<string, mixed>  $context  must answer what, expected vs actual,
     *                                         and the decision taken — redacted
     */
    public function warn(string $message, array $context = []): void;
}
