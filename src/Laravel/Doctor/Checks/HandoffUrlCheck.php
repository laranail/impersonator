<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

/**
 * The token driver is useless without somewhere to send the operator.
 */
final class HandoffUrlCheck extends Check
{
    public function name(): string
    {
        return 'Handoff URLs';
    }

    public function description(): string
    {
        return 'Whether a cross-domain handoff has a base domain to build accept URLs against.';
    }

    public function run(): DoctorResult
    {
        if ($this->settings->string('driver', 'session') !== 'token') {
            return DoctorResult::skip('The token driver is not selected, so accept URLs are not used.');
        }

        return $this->settings->nullableString('urls.base_domain') === null
            ? DoctorResult::warn(
                'The token driver is selected but impersonator.urls.base_domain is unset, so accept '
                .'URLs are built against the current host. For a cross-domain handoff — the reason '
                .'to pick this driver — that is the wrong host.',
            )
            : DoctorResult::pass('A base domain is configured for accept URLs.');
    }
}
