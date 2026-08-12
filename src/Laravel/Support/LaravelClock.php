<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use DateTimeImmutable;
use Illuminate\Support\Carbon;
use Psr\Clock\ClockInterface;

/**
 * The current time, as the application understands it.
 *
 * Reading `new DateTimeImmutable` directly would bypass `Carbon::setTestNow()`, and
 * that is not merely a testing inconvenience: every expiry decision in this package —
 * `max_duration`, token TTL, stale-row reconciliation — would be answered against the
 * system clock while the rest of the application answered against Carbon's. A time
 * travel test would then pass on code that never expires anything.
 *
 * PSR-20 so the Core layer can depend on the interface without knowing about Carbon.
 */
final readonly class LaravelClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        // Carbon::now() honours setTestNow and the application timezone; converting
        // rather than returning it keeps Core's contract on plain DateTimeImmutable.
        return DateTimeImmutable::createFromInterface(Carbon::now());
    }
}
