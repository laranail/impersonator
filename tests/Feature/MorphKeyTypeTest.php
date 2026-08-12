<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;

/*
| `morphs.key_type` is read only when the migration runs, so the only way to verify it is to run
| the migration again under each setting. Worth doing: a bad column type here does not fail until
| somebody impersonates a model whose key does not fit, which is long after deploy.
*/

/** @return array<string, string> column => database type */
function auditColumnTypes(): array
{
    $types = [];

    foreach (Schema::getColumns('impersonator_audits') as $column) {
        $types[(string) $column['name']] = strtolower((string) $column['type_name']);
    }

    return $types;
}

it('stores morph ids as strings by default', function (): void {
    // The default has to stay `string`: it is what lets an int-keyed User and a UUID-keyed Vendor
    // share one audit table, which is the point of a multi-model allowlist.
    expect(auditColumnTypes()['impersonatable_id'])->toBeIn(['varchar', 'character varying', 'text']);
});

it('migrates every documented key type', function (string $keyType, array $expected): void {
    config()->set('impersonator.morphs.key_type', $keyType);

    // Everything, via the harness helper rather than a list maintained here — a hand-written list is
    // what silently fell behind when a fifth table arrived. Forced, because this re-runs the migration
    // inside a single test, where the helper's per-test SQLite shortcut does not apply.
    $this->dropAllTables(force: true);

    $this->packageMigration()->up();

    $types = auditColumnTypes();

    expect($types)->toHaveKeys(['impersonatable_type', 'impersonatable_id'])
        ->and($types['impersonatable_id'])->toBeIn($expected)
        // The type half is always a string, whatever the id half is.
        ->and($types['impersonatable_type'])->toBeIn(['varchar', 'character varying', 'text']);
})->with([
    'numeric' => ['numeric', ['integer', 'bigint', 'int8']],
    // Each driver names these differently: PostgreSQL reports a fixed-width char as `bpchar`
    // (blank-padded) and has a native `uuid` type, while SQLite and MySQL report varchar.
    'uuid' => ['uuid', ['varchar', 'character varying', 'uuid', 'char', 'bpchar', 'text']],
    'ulid' => ['ulid', ['varchar', 'character varying', 'char', 'bpchar', 'text']],
    'unknown falls back to string' => ['nonsense', ['varchar', 'character varying', 'text']],
]);
