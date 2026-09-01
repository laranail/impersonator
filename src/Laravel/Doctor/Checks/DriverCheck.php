<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;
use Throwable;

final class DriverCheck extends Check
{
    public function name(): string
    {
        return 'Driver';
    }

    public function description(): string
    {
        return 'Whether the configured impersonation driver resolves.';
    }

    public function run(): DoctorResult
    {
        $manager = $this->resolve(ImpersonationManager::class);
        $driver = $this->settings->string('driver', 'session');

        if ($manager === null) {
            return DoctorResult::fail('The impersonation manager could not be built, so the driver was not checked.');
        }

        try {
            $manager->driver($driver);
        } catch (Throwable $e) {
            return DoctorResult::fail(sprintf('[%s] does not resolve: %s', $driver, $e->getMessage()));
        }

        return DoctorResult::pass(sprintf('[%s] resolves.', $driver));
    }
}
