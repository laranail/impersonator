<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Impersonator\Laravel\Support\PackageTables;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

/**
 * Whether RLS is switched on over **this package's own** tables.
 *
 * The failure this catches is nasty and silent. If a policy hides audit rows from `SELECT`, the HMAC
 * chain breaks in a way that looks like tampering: each row's digest is computed over its
 * predecessor's, so a hidden predecessor makes `verify-audit` report a break that never happened. An
 * export would return an empty trail for the same reason, and both read as evidence of an attack
 * rather than as a misconfiguration.
 *
 * `FORCE ROW LEVEL SECURITY` is worse still: it applies to the table owner too, so even the migration's
 * own user is filtered.
 *
 * The recommendation is to exempt these tables, or to policy them explicitly for the application's
 * database user. They hold the record *about* access rather than tenant data, so scoping them by tenant
 * is answering the wrong question.
 */
final class RowLevelSecurityCheck extends Check
{
    public function name(): string
    {
        return 'Row-level security';
    }

    public function description(): string
    {
        return 'Whether RLS is enabled on the package tables, which would break the audit chain.';
    }

    public function run(): DoctorResult
    {
        $connections = $this->resolve(ConnectionResolverInterface::class);

        if ($connections === null) {
            return DoctorResult::skip('The connection resolver is unavailable, so this was not checked.');
        }

        return $this->safely(function () use ($connections): DoctorResult {
            $connection = $connections->connection($this->settings->nullableString('audit.connection'));

            // Narrowed to the concrete `Connection`, because `getDriverName()` is not on
            // `ConnectionInterface`. A custom implementation may legitimately lack it, and that is a
            // connection this check cannot make claims about either way.
            if (! $connection instanceof Connection) {
                return DoctorResult::skip('The audit connection does not report a driver, so this was not checked.');
            }

            if ($connection->getDriverName() !== 'pgsql') {
                return DoctorResult::skip(sprintf(
                    'The audit connection uses [%s]; row-level security is a PostgreSQL feature.',
                    $connection->getDriverName(),
                ));
            }

            $tables = PackageTables::names($this->settings);

            // `pg_class` rather than `information_schema`, because the RLS flags are PostgreSQL-specific
            // and not exposed by the standard views.
            $rows = $connection->select(
                'select relname, relrowsecurity, relforcerowsecurity from pg_class where relname = any(?)',
                ['{' . implode(',', $tables) . '}'],
            );

            $enabled = [];

            foreach ($rows as $row) {
                // `select()` is typed `array<mixed>`, and a host may have set a different fetch mode, so
                // the row shape is checked rather than assumed.
                if (! is_object($row)) {
                    continue;
                }

                $name = $row->relname ?? null;
                $on = ($row->relrowsecurity ?? false) === true;
                $forced = ($row->relforcerowsecurity ?? false) === true;

                if (is_string($name) && ($on || $forced)) {
                    $enabled[] = $name . ($forced ? ' (FORCED)' : '');
                }
            }

            return $enabled === []
                ? DoctorResult::pass('Row-level security is not enabled on any package table.')
                : DoctorResult::fail(
                    'Row-level security is enabled on: ' . implode(', ', $enabled)
                    . '. A policy that hides an audit row makes verify-audit report a chain break that '
                    . 'never happened — the digest is computed over the previous row — and makes an '
                    . 'export return an empty trail. Exempt these tables, or policy them explicitly '
                    . 'for the application\'s database user.',
                    ['tables' => $enabled],
                );
        }, 'inspect row-level security on the audit connection');
    }
}
