<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Illuminate\Support\Str;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

final class MaxDurationCheck extends Check
{
    public function name(): string
    {
        return 'Maximum duration';
    }

    public function description(): string
    {
        return 'Whether an impersonation is force-ended after a bounded window.';
    }

    public function run(): DoctorResult
    {
        $max = $this->settings->positiveIntOrNull('limits.max_duration');

        return $max === null
            ? DoctorResult::warn(
                'impersonator.limits.max_duration is unlimited, so an impersonation left open stays '
                . 'open. An abandoned session inside a customer account is the one that shows up in '
                . 'an audit with no explanation.',
            )
            : DoctorResult::pass(sprintf(
                'Impersonations are force-ended after %d %s.',
                $max,
                Str::plural('minute', $max),
            ));
    }
}
