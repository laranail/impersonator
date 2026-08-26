<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;
use Simtabi\Laranail\Enumerator\Providers\EnumeratorServiceProvider;
use Simtabi\Laranail\Impersonator\Laravel\Providers\ImpersonatorServiceProvider;
use Simtabi\Laranail\Package\Tools\Providers\PackageToolsServiceProvider;

abstract class TestCase extends Orchestra
{
    /**
     * @return list<class-string>
     *
     * The two family providers are listed explicitly because Testbench does not run Laravel's
     * package discovery. A real install gets them from `extra.laravel.providers` in each package's
     * composer.json, and omitting them here produces the nastiest kind of test gap — one that
     * silently no-ops in tests while working in production:
     *
     *  - without package-tools, `DoctorService` is unbound and the shared-doctor registration does
     *    nothing;
     *  - without enumerator, `TranslatorAdapter` is unbound and every enum `label()` skips the
     *    translator and falls back to its `#[Label]` attribute — so a translation test would assert
     *    the English string and pass.
     */
    protected function getPackageProviders($app): array
    {
        return [
            EnumeratorServiceProvider::class,
            PackageToolsServiceProvider::class,
            ImpersonatorServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $config = $app->make('config');

        // Generated rather than committed. A literal `base64:` key in phpunit.xml is a valid
        // AES-256 key by construction, so secret scanners flag it — correctly, by their rules,
        // even though it only ever encrypted an in-memory test session. Generating it here removes
        // the detector surface entirely and nothing is lost: no test asserts a fixed key.
        $config->set('app.key', 'base64:' . base64_encode(random_bytes(32)));

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', $this->connectionConfig());

        // The enforcement middleware is appended to `web` in a real install. Tests
        // exercise it explicitly on purpose: appending it globally here would make
        // every unrelated test depend on middleware ordering, and hide which test is
        // actually covering the enforcement.
        $config->set('laranail.impersonator.routes.auto_append_to_groups', []);
    }

    /**
     * The connection under test, SQLite in memory unless told otherwise.
     *
     * Not named `testConnection`: PHPUnit treats any `test`-prefixed method as a test case, so that
     * name turns a helper into a silently-failing test — and Pint's method-casing fixer rewrites it
     * to `test_connection`, which is worse.
     *
     * Switchable because SQLite cannot prove everything this package claims. `lockForUpdate()`
     * compiles to an empty string there, so the concurrency guarantees need a database that
     * actually locks; and SQLite emits unqualified table names, which is why a parsing bug that
     * broke `read_only` on PostgreSQL survived a green suite.
     *
     *   IMPERSONATOR_TEST_DB=pgsql vendor/bin/pest
     *   IMPERSONATOR_TEST_DB=mysql vendor/bin/pest
     *
     * @return array<string, mixed>
     */
    protected function connectionConfig(): array
    {
        $driver = getenv('IMPERSONATOR_TEST_DB') ?: 'sqlite';

        return match ($driver) {
            'pgsql' => [
                'driver' => 'pgsql',
                'host' => getenv('IMPERSONATOR_TEST_DB_HOST') ?: '127.0.0.1',
                'port' => getenv('IMPERSONATOR_TEST_DB_PORT') ?: '5432',
                'database' => getenv('IMPERSONATOR_TEST_DB_NAME') ?: 'impersonator_test',
                'username' => getenv('IMPERSONATOR_TEST_DB_USER') ?: get_current_user(),
                'password' => getenv('IMPERSONATOR_TEST_DB_PASSWORD') ?: '',
                'charset' => 'utf8',
                'prefix' => '',
                'search_path' => 'public',
                'sslmode' => 'prefer',
            ],
            'mysql' => [
                'driver' => 'mysql',
                'host' => getenv('IMPERSONATOR_TEST_DB_HOST') ?: '127.0.0.1',
                'port' => getenv('IMPERSONATOR_TEST_DB_PORT') ?: '3306',
                'database' => getenv('IMPERSONATOR_TEST_DB_NAME') ?: 'impersonator_test',
                'username' => getenv('IMPERSONATOR_TEST_DB_USER') ?: 'root',
                'password' => getenv('IMPERSONATOR_TEST_DB_PASSWORD') ?: '',
                'charset' => 'utf8mb4',
                'collation' => 'utf8mb4_unicode_ci',
                'prefix' => '',
            ],
            default => [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
            ],
        };
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
        // A clean slate per test, because only SQLite `:memory:` gives one for free. A real driver
        // keeps whatever the previous test created, so an unconditional `up()` collides on the
        // second test — and so does each test file's own `Schema::create('users', …)`.
        //
        // Everything is dropped rather than a named list, since test files create their own fixture
        // tables (`users`, `vendors`, `sessions`, …) and a list would silently fall behind.
        $this->dropAllTables();

        $this->packageMigration()->up();
    }

    /**
     * Drop everything on the test connection.
     *
     * Protected rather than private so a test that re-runs the migration can reuse it. A test keeping
     * its own list of tables to drop is what fell behind the moment a fifth table was added — and it
     * failed as "table already exists", which reads like a migration bug rather than a stale fixture.
     */
    protected function dropAllTables(bool $force = false): void
    {
        $schema = Schema::connection('testing');

        if (! $force && $schema->getConnection()->getDriverName() === 'sqlite') {
            // Skipped per test on SQLite as a cost optimisation: `:memory:` is a new database each
            // time, and enumerating it would cost a query per test across the whole suite.
            //
            // `$force` exists for a test that re-runs the migration *within* one test, where the
            // tables genuinely are there and the assumption above does not hold.
            return;
        }

        // Foreign keys point between these (the trail references the audit row), so constraint
        // checking goes off for the duration rather than the drops being hand-ordered.
        //
        // `migrations` goes too, and that is the fix for a real failure. Keeping the ledger while
        // dropping the tables it describes leaves the two disagreeing: a later `artisan migrate` —
        // which the Passport test runs to build `oauth_clients` — reads the ledger, concludes
        // everything is already applied, and creates nothing. The tables it needs are gone, so every
        // assertion fails with "relation does not exist" on a driver that keeps state between tests.
        $schema->withoutForeignKeyConstraints(function () use ($schema): void {
            foreach ($schema->getTables() as $table) {
                $name = is_array($table) ? ($table['name'] ?? null) : null;

                if (is_string($name)) {
                    $schema->drop($name);
                }
            }
        });
    }

    /**
     * Release the connection between tests.
     *
     * Testbench builds a fresh application per test, and on a real driver each one opens its own
     * PDO connection. Left alone they accumulate until the server refuses — PostgreSQL answers
     * "sorry, too many clients already" a few hundred tests in, which looks like a package failure
     * and is not one.
     */
    protected function tearDown(): void
    {
        // Not for SQLite. An in-memory database *is* the connection, so purging it destroys the
        // schema — and Testbench still touches it during its own teardown, which surfaces as
        // "no such table: migrations" in whichever test ran real migrations. There is no connection
        // limit to protect against there anyway.
        if ($this->app !== null && getenv('IMPERSONATOR_TEST_DB') !== false
            && getenv('IMPERSONATOR_TEST_DB') !== 'sqlite') {
            $this->app->make('db')->purge('testing');
        }

        parent::tearDown();
    }

    protected function packageMigration(): Migration
    {
        return require dirname(__DIR__) . '/database/migrations/create_impersonator_tables.php.stub';
    }
}
