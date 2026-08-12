<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Enums;

/**
 * How a failure must be handled, decided by the state continuing would leave.
 *
 * Per the failure-handling standard: behaviour is keyed on consequence, never on
 * environment. The same path runs in dev, CI and production — a failure unsafe to
 * continue past crashes everywhere, and one safe to continue past degrades
 * everywhere. There is deliberately no third case and no runtime override, since
 * a "force past it" lever reintroduces exactly the masking this prevents.
 */
enum Criticality
{
    /**
     * Continuing would leave an unsafe, incorrect or insecure state. Fails fast.
     * A dead program does less damage than a crippled one.
     */
    case Critical;

    /** Continuing leaves a safe, reduced state. Reports, records, and continues. */
    case Degradable;

    /** What the runner did, for the report's `decision` field. */
    public function decision(): string
    {
        return match ($this) {
            self::Critical => 'crashed',
            self::Degradable => 'degraded-and-continued',
        };
    }
}
