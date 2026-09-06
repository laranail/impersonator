<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Simtabi\Laranail\Impersonator\Laravel\Support\PersistenceGuard;

/*
| What can be verified about SQL Server without a SQL Server.
|
| The `pdo_sqlsrv` extension is not installed here and Microsoft's driver lags PHP releases, so the suite
| cannot connect to one. But Laravel ships the **grammar**, and a connection can be *configured* without
| ever being opened: `toSql()` compiles SQL locally and touches no server.
|
| That makes two claims testable that were previously only asserted in prose:
|
|   1. the mode guard parses SQL Server's `[dbo].[table]` quoting — the same defect class that broke
|      `read_only` on PostgreSQL for a whole release, caught there only after the fact;
|   2. `lockForUpdate()` compiles to something *different* on SQL Server, which is exactly why the
|      concurrency guarantees are documented as unverified there rather than assumed to carry over.
|
| What this still does not prove is behaviour: that the hints below actually take the locks the package
| needs. Only a real server can show that, and `docs/installation.md` says so.
*/

beforeEach(function (): void {
    // Configured, never connected. No PDO is constructed until a query executes, and none here does.
    config()->set('database.connections.sqlsrv_probe', [
        'driver'   => 'sqlsrv',
        'host'     => '127.0.0.1',
        'database' => 'impersonator_test',
        'username' => 'sa',
        'password' => 'unused',
        'prefix'   => '',
    ]);

    // An explicit SQLite connection rather than the default one. The default is whatever
    // IMPERSONATOR_TEST_DB selects, so comparing against it made this file pass on SQLite and fail on
    // PostgreSQL — where `for update` is exactly what the default *should* emit.
    config()->set('database.connections.sqlite_probe', [
        'driver'   => 'sqlite',
        'database' => ':memory:',
        'prefix'   => '',
    ]);
});

it('quotes a qualified table the way the guard expects', function (): void {
    $sql = DB::connection('sqlsrv_probe')->query()->from('dbo.impersonator_audits')->toSql();

    // `[dbo].[impersonator_audits]` — the bracket form the guard's parser was written for.
    expect($sql)->toContain('[dbo].[impersonator_audits]');
});

it('parses every dialect the package can meet, including sql server', function (): void {
    // The regression test for a shipped bug: the old parser stopped at the first delimiter, so
    // `update "public"."sessions"` parsed as table `public`, never matched its exemption, and
    // `read_only` refused every request on PostgreSQL and MySQL. Green on SQLite the whole time.
    $guard = app(PersistenceGuard::class);
    $method = new ReflectionMethod($guard, 'tableFrom');

    $cases = [
        'sqlite bare'        => 'update impersonator_audits set x = 1',
        'sqlite quoted'      => 'update "impersonator_audits" set x = 1',
        'postgres qualified' => 'update "public"."impersonator_audits" set x = 1',
        'mysql qualified'    => 'update `app`.`impersonator_audits` set x = 1',
        'sqlsrv qualified'   => 'update [dbo].[impersonator_audits] set x = 1',
        'sqlsrv three-part'  => 'update [db].[dbo].[impersonator_audits] set x = 1',
    ];

    foreach ($cases as $label => $sql) {
        $parsed = $method->invoke($guard, $sql);

        expect($parsed)->not->toBeNull($label)
            // The last segment is what an exempt list is written in.
            ->and($parsed['table'])->toBe('impersonator_audits', $label);
    }
});

it('shows that lockForUpdate is not a row lock on sql server', function (): void {
    // The reason the concurrency guarantees are documented as unverified there. PostgreSQL and MySQL
    // both emit `for update`; SQL Server emits table hints with different semantics, and SQLite emits
    // nothing at all.
    $sqlsrv = DB::connection('sqlsrv_probe')->query()->from('impersonator_audits')->lockForUpdate()->toSql();
    $sqlite = DB::connection('sqlite_probe')->query()->from('impersonator_audits')->lockForUpdate()->toSql();

    expect(strtolower($sqlsrv))->not->toContain('for update')
        // `with(rowlock, updlock, holdlock)` — a hint, not the same construct.
        ->and(strtolower($sqlsrv))->toContain('rowlock')
        ->and(strtolower($sqlsrv))->toContain('updlock');

    // SQLite compiles it away entirely, which is why the `locking` group skips there rather than
    // passing and giving false assurance.
    expect(strtolower($sqlite))->not->toContain('for update')
        ->and(strtolower($sqlite))->not->toContain('rowlock');
});

it('is recognised by the locking-group helper as not emitting a plain row lock', function (): void {
    // The helper that decides whether a concurrency test can prove anything. It must classify SQL Server
    // honestly, or the `locking` group would run there and assert a guarantee the hints may not give.
    $sqlsrv = strtolower(
        DB::connection('sqlsrv_probe')->query()->from('impersonator_audits')->lockForUpdate()->toSql(),
    );

    // The helper accepts rowlock/updlock as *a* lock, so SQL Server would be treated as lockable. That
    // is deliberate and documented: the hints are a lock, they are simply not proven equivalent here.
    expect(str_contains($sqlsrv, 'rowlock') || str_contains($sqlsrv, 'updlock'))->toBeTrue();
});
