<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

final class GuardsCheck extends Check
{
    public function name(): string
    {
        return 'Guards';
    }

    public function description(): string
    {
        return 'Whether every guard the package will authenticate against is defined.';
    }

    public function run(): DoctorResult
    {
        $manager = $this->resolve(ImpersonationManager::class);

        if ($manager === null) {
            return DoctorResult::fail('The impersonation manager could not be built, so guards were not checked.');
        }

        return $this->safely(function () use ($manager): DoctorResult {
            $configured = [
                $this->settings->string('guards.impersonator', 'web'),
                $this->settings->string('guards.target', 'web'),
            ];

            foreach ($manager->targets()->all() as $type) {
                $guard = $type->guard;

                if (is_string($guard) && $guard !== '') {
                    $configured[] = $guard;
                }
            }

            $configured = array_unique($configured);
            $unknown = [];

            foreach ($configured as $guard) {
                if (! is_array(config('auth.guards.' . $guard))) {
                    $unknown[] = $guard;
                }
            }

            return $unknown === []
                ? DoctorResult::pass(sprintf('All configured guards exist: %s.', implode(', ', $configured)))
                : DoctorResult::fail(
                    sprintf('Guards not defined in config/auth.php: %s.', implode(', ', $unknown)),
                    ['unknown' => $unknown],
                );
        }, 'inspect the configured guards');
    }
}
