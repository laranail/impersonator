<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Laravel\Support\PersistenceGuard;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

/*
| What keeps this package portable across drivers.
|
| Three columns are JSON — the audit `metadata`, the trail `payload`, the approval `request`. On MySQL
| that is a native JSON type with its own comparison rules; on SQLite and PostgreSQL it is something
| else again. Nothing currently *queries inside* them, and that is precisely what keeps the package
| driver-independent. This file pins that, so a future `whereJsonContains` does not silently make the
| package MySQL-only.
*/

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('impersonator.limits.state_cache.ttl', 0);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

it('never queries inside a json column', function (): void {
    // The assertion that keeps the package portable. `whereJsonContains` and friends compile to
    // driver-specific SQL — `JSON_CONTAINS` on MySQL, a `::jsonb` cast on PostgreSQL, and on SQLite
    // something that works only if the JSON1 extension is compiled in.
    $offenders = [];

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(dirname(__DIR__, 2) . '/src')) as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $src = (string) file_get_contents($file->getPathname());

        foreach (['whereJsonContains', 'whereJsonLength', 'whereJsonDoesntContain', '->jsonb', 'JSON_CONTAINS', 'JSON_EXTRACT'] as $needle) {
            if (str_contains($src, $needle)) {
                $offenders[] = $file->getFilename() . ' uses ' . $needle;
            }
        }
    }

    expect($offenders)->toBe([]);
});

it('round-trips json metadata on whichever driver is under test', function (): void {
    // Written and read back as an array rather than compared as a string: MySQL normalises native JSON
    // (key order, whitespace), so asserting on the serialised form would pass on SQLite and fail there.
    $metadata = [
        'ticket' => 'SUP-4182',
        'nested' => ['depth' => 2, 'flag' => true, 'null' => null],
        'unicode' => 'café — naïve',
        'quotes' => 'say "hi"',
        'backslash' => 'C:\\Users\\admin',
    ];

    Impersonator::enter($this->target, metadata: $metadata);

    $row = ImpersonationAudit::query()->find((string) Impersonator::current()?->auditId);
    $stored = $row?->getAttribute('metadata');

    expect($stored)->toBeArray()
        ->and($stored['ticket'])->toBe('SUP-4182')
        ->and($stored['nested']['depth'])->toBe(2)
        ->and($stored['nested']['flag'])->toBeTrue()
        ->and($stored['unicode'])->toBe('café — naïve')
        ->and($stored['quotes'])->toBe('say "hi"')
        ->and($stored['backslash'])->toBe('C:\\Users\\admin');
});

it('stores morph ids as strings whatever the driver reports', function (): void {
    // One audit table holding an int-keyed User beside a UUID-keyed Vendor is the point of a
    // multi-model allowlist, and every driver types that column differently.
    Impersonator::enter($this->target);

    $row = ImpersonationAudit::query()->find((string) Impersonator::current()?->auditId);

    expect($row?->getAttribute('impersonatable_id'))->toBeString();
});

it('parses a qualified table name from whatever this driver emits', function (): void {
    // The bug that shipped: `update "public"."sessions"` parsed as table `public`, so the exempt list
    // never matched and `read_only` refused every request on PostgreSQL and MySQL. Green on SQLite,
    // which emits unqualified names.
    $emitted = DB::connection()->query()->from('impersonator_audits')->toSql();
    $driver = DB::connection()->getDriverName();

    // Whatever quoting this driver uses, the guard has to find the table in it.
    $guard = new ReflectionClass(PersistenceGuard::class);
    $method = $guard->getMethod('tableFrom');

    $parsed = $method->invoke(app(PersistenceGuard::class),
        'update ' . str_replace('select * from ', '', $emitted) . ' set "x" = 1');

    expect($parsed)->not->toBeNull()
        ->and($parsed['table'])->toBe('impersonator_audits', "driver [{$driver}] emitted [{$emitted}]");
});
