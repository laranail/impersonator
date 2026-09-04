<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

final class MasterSwitchCheck extends Check
{
    public function name(): string
    {
        return 'Master switch';
    }

    public function description(): string
    {
        return 'Whether impersonation is enabled at all.';
    }

    public function run(): DoctorResult
    {
        return $this->settings->bool('enabled', true)
            ? DoctorResult::pass('Impersonation is enabled.')
            : DoctorResult::warn(
                'impersonator.enabled is false, so every enter is refused. Revocation still works, '
                . 'which is deliberate: turning the feature off during an incident must not also '
                . 'remove the ability to kill the sessions already running.',
            );
    }
}
