<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Illuminate\Support\Str;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

/**
 * The extension ceiling, which is what makes the duration window mean anything.
 *
 * Reported as a warning rather than a pass when unbounded: a configuration offering unlimited
 * extensions reads as a ten-minute limit and behaves as no limit at all, and that gap between what
 * the config says and what it does is worth naming out loud.
 */
final class ExtensionCheck extends Check
{
    public function name(): string
    {
        return 'Extension';
    }

    public function description(): string
    {
        return 'Whether extending a live impersonation is bounded by a real ceiling.';
    }

    public function run(): DoctorResult
    {
        if (! $this->settings->bool('limits.extension.enabled', true)) {
            return DoctorResult::pass('Extending a live impersonation is switched off.');
        }

        $minutes = $this->settings->int('limits.extension.minutes', 10);
        $count = $this->settings->positiveIntOrNull('limits.extension.max');
        $total = $this->settings->positiveIntOrNull('limits.extension.max_total_duration');
        $max = $this->settings->positiveIntOrNull('limits.max_duration');

        if ($count === null && $total === null) {
            return DoctorResult::warn(
                'Extensions are unlimited in both count and total duration, so limits.max_duration '
                .'bounds nothing — an impersonation can run indefinitely a window at a time. Set '
                .'limits.extension.max_total_duration to a real ceiling.',
            );
        }

        if ($max === null) {
            return DoctorResult::warn(
                'Extension is on but limits.max_duration is unlimited, so there is no deadline to '
                .'extend. Set a duration, or switch limits.extension.enabled off.',
            );
        }

        return DoctorResult::pass(sprintf(
            'Operators may add %d %s%s, up to %s.',
            $minutes,
            Str::plural('minute', $minutes),
            $count === null
                ? ' any number of times'
                : sprintf(' at most %d %s', $count, Str::plural('time', $count)),
            $total === null
                ? 'no total ceiling'
                : sprintf('%d %s in total', $total, Str::plural('minute', $total)),
        ));
    }
}
