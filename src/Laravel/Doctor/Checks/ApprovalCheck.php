<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Illuminate\Support\Str;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

final class ApprovalCheck extends Check
{
    public function name(): string
    {
        return 'Break-glass approval';
    }

    public function description(): string
    {
        return 'Whether a second operator must authorise an impersonation, and for which modes.';
    }

    public function run(): DoctorResult
    {
        if (! $this->settings->bool('approval.require', false)) {
            return DoctorResult::pass('Not required.');
        }

        $exempt = $this->settings->stringList('approval.except_modes');

        return DoctorResult::pass(sprintf(
            'Required for every mode except: %s. Requests expire after %d %s.',
            $exempt === [] ? 'none' : implode(', ', $exempt),
            $ttl = $this->settings->int('approval.ttl', 15),
            Str::plural('minute', $ttl),
        ));
    }
}
