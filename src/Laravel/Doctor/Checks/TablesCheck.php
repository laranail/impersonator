<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\DbTools\Guard\DatabaseGuard;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Impersonator\Laravel\Support\PackageTables;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

final class TablesCheck extends Check
{
    public function name(): string
    {
        return 'Tables';
    }

    public function description(): string
    {
        return sprintf('Whether all %d package tables exist on the audit connection.', PackageTables::count());
    }

    /**
     * Probed through db-tools' DatabaseGuard rather than `Schema::hasTable()`.
     *
     * It is non-throwing and self-bootstrapping: a bare `hasTable()` raises when the database is
     * simply unreachable, which is a different diagnosis from "the migration has not been run" and
     * the one the operator most needs told apart.
     */
    public function run(): DoctorResult
    {
        $connection = $this->settings->nullableString('audit.connection');

        return $this->safely(function () use ($connection): DoctorResult {
            $missing = [];

            foreach (PackageTables::names($this->settings) as $table) {
                if (! DatabaseGuard::tableExists($table, $connection)) {
                    $missing[] = $table;
                }
            }

            return $missing === []
                ? DoctorResult::pass(sprintf('All %d tables exist.', PackageTables::count()))
                : DoctorResult::fail(
                    sprintf(
                        'Missing: %s. Publish and run the migration: php artisan vendor:publish '
                        .'--tag=impersonator-migrations && php artisan migrate',
                        implode(', ', $missing),
                    ),
                    ['missing' => $missing],
                );
        }, sprintf('reach the audit connection [%s]', $connection ?? 'default'));
    }
}
