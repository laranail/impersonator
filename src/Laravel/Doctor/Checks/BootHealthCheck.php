<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\Impersonator\Core\Support\FailureReport;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

/**
 * Anything that degraded during boot.
 *
 * The most valuable check here. A degradable boot operation that failed — routes not registered, a
 * Blade component missing, listeners not attached — leaves an application that starts cleanly and
 * quietly lacks a feature.
 */
final class BootHealthCheck extends Check
{
    public function name(): string
    {
        return 'Boot health';
    }

    public function description(): string
    {
        return 'Whether every boot registration completed, or something degraded silently.';
    }

    public function run(): DoctorResult
    {
        $health = $this->resolve(FailureReport::class);

        if ($health === null) {
            return DoctorResult::skip('The boot report is unavailable, so nothing can be said about it.');
        }

        if ($health->isHealthy()) {
            return DoctorResult::pass('Every registration completed.');
        }

        $lines = [];
        $detail = [];

        foreach ($health->degraded() as $operation => $failure) {
            $lines[] = sprintf('%s degraded: %s (%s)', $operation, $failure['message'], $failure['type']);
            $detail[(string) $operation] = (string) $failure['message'];
        }

        // Joined into one result rather than one per failure, because the contract returns a single
        // DoctorResult. Nothing is lost: each operation is still named, and `detail` keeps them
        // separable for anything consuming the report programmatically.
        return DoctorResult::fail(implode(' | ', $lines), $detail);
    }
}
