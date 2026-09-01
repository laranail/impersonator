<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

/**
 * Other impersonation packages in the same application.
 *
 * Not a failure — two packages can coexist. But both will register routes, both may write session
 * keys, and a leave through one will not end an impersonation started by the other, which produces
 * an audit trail that disagrees with itself.
 *
 * The list comes from config rather than a constant so an application can add whatever else it knows
 * conflicts — a Filament plugin, an internal package — without waiting on this one.
 */
final class ConflictingPackagesCheck extends Check
{
    public function name(): string
    {
        return 'Conflicting packages';
    }

    public function description(): string
    {
        return 'Whether another impersonation package is installed alongside this one.';
    }

    public function run(): DoctorResult
    {
        $found = [];

        foreach ($this->settings->array('doctor.conflicting_packages') as $class => $package) {
            if (is_string($class) && $class !== '' && class_exists($class)) {
                $found[] = is_string($package) ? $package : $class;
            }
        }

        return $found === []
            ? DoctorResult::pass('No other impersonation package detected.')
            : DoctorResult::warn(
                sprintf(
                    'Also installed: %s. Two impersonation packages both register routes and session '
                    .'state, and leaving through one does not end an impersonation started by the '
                    .'other — which produces an audit trail that disagrees with itself.',
                    implode(', ', $found),
                ),
                ['packages' => $found],
            );
    }
}
