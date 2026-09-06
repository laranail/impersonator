<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Throwable;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

final class AdapterCheck extends Check
{
    public function name(): string
    {
        return 'Adapter';
    }

    public function description(): string
    {
        return 'Whether the configured auth adapter resolves.';
    }

    public function run(): DoctorResult
    {
        $manager = $this->resolve(ImpersonationManager::class);
        $adapter = $this->settings->string('adapter', 'session');

        if ($manager === null) {
            return DoctorResult::fail('The impersonation manager could not be built, so the adapter was not checked.');
        }

        try {
            $manager->adapter($adapter);
        } catch (Throwable $e) {
            return DoctorResult::fail(sprintf('[%s] does not resolve: %s', $adapter, $e->getMessage()));
        }

        return DoctorResult::pass(sprintf('[%s] resolves.', $adapter));
    }
}
