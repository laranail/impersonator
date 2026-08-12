<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests;

use Illuminate\Database\Migrations\Migration;
use Orchestra\Testbench\TestCase as Orchestra;
use Simtabi\Laranail\Impersonator\Laravel\Providers\ImpersonatorServiceProvider;

abstract class TestCase extends Orchestra
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [ImpersonatorServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $config = $app->make('config');

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // The enforcement middleware is appended to `web` in a real install. Tests
        // exercise it explicitly on purpose: appending it globally here would make
        // every unrelated test depend on middleware ordering, and hide which test is
        // actually covering the enforcement.
        $config->set('impersonator.routes.auto_append_to_groups', []);
    }

    /**
     * Run the package's own migrations.
     *
     * Loaded from the publishable stub rather than a duplicate copy under tests/, so
     * the suite exercises the exact schema consumers get. A second, test-only schema
     * is how a migration bug ships green.
     */
    protected function defineDatabaseMigrations(): void
    {
        $this->packageMigration()->up();
    }

    protected function packageMigration(): Migration
    {
        return require dirname(__DIR__) . '/database/migrations/create_impersonator_tables.php.stub';
    }
}
