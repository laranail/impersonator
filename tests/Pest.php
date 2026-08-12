<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Simtabi\Laranail\Impersonator\Tests\TestCase;

// Feature tests need a booted application; Unit and Arch tests deliberately do
// not get one. That split is what keeps the Core layer honest — a Core test that
// accidentally relies on a container would fail rather than quietly pass.
uses(TestCase::class)->in('Feature');

/**
 * Whether the current connection actually emits a row lock.
 *
 * `SQLiteGrammar::compileLock()` returns an empty string, so `lockForUpdate()` on SQLite is a
 * silent no-op. Every guarantee this package makes about concurrency — the
 * `max_active_per_impersonator` cap, and the approval quorum recount — is a count-then-write
 * guarded by that lock. Run those assertions on SQLite and they pass while proving nothing about
 * the race they exist for.
 *
 * So tests that need a real lock ask this first and skip *loudly* when the answer is no. A test
 * that cannot prove its claim should say so; silently passing is worse than not having it.
 */
function connectionEmitsRowLocks(): bool
{
    $connection = DB::connection();

    $sql = $connection->query()->from('impersonator_audits')->lockForUpdate()->toSql();

    return str_contains(strtolower($sql), 'for update')
        || str_contains(strtolower($sql), 'rowlock')
        || str_contains(strtolower($sql), 'updlock');
}

/** Skip with a reason that names the driver, so a green run is never mistaken for proof. */
function requiresRowLocks(): void
{
    if (connectionEmitsRowLocks()) {
        return;
    }

    $driver = DB::connection()->getDriverName();

    test()->markTestSkipped(
        "The [{$driver}] driver compiles lockForUpdate() to a no-op, so this test cannot prove the "
        . 'race it exists for. Run the `locking` group against PostgreSQL or MySQL.',
    );
}
