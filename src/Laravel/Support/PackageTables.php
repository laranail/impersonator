<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

/**
 * Every table this package creates, as config key => default name.
 *
 * One list, because two hand-maintained copies is how the last drift happened: the approval-chain work
 * added a fifth table, and the doctor's existence check kept looking for four. The result was the worst
 * kind of gap — entering worked, requesting approval worked, and the first *decision* failed, so the
 * break surfaced on the one path a support engineer reaches only during an incident.
 *
 * Read by the doctor's `TablesCheck` and `RowLevelSecurityCheck` — named in prose rather than with
 * `{@see}` tags, because those resolve to imports and a Support class importing the Doctor checks that
 * import it inverts the dependency. A sixth table now needs adding here once, and both checks see it.
 *
 * ### The migration stub deliberately does not read this
 *
 * `database/migrations/create_impersonator_tables.php.stub` repeats the `config(...)` calls instead.
 * That is not an oversight: the stub is *published into the host application*, where it has to keep
 * running long after — and even if — this package is removed. A published migration that imports a
 * class from a package the application no longer requires cannot roll back. So the stub stays
 * standalone, and `DocumentedClaimsTest` asserts the two agree by inspecting the schema the migration
 * actually builds, which is the check that would have caught the drift.
 */
final class PackageTables
{
    /** @return array<string, string> config key => default table name */
    public static function map(): array
    {
        return [
            'audit.table' => 'impersonator_audits',
            'trail.table' => 'impersonator_audit_events',
            'tokens.table' => 'impersonator_tokens',
            'approval.table' => 'impersonator_approval_requests',
            'approval.decisions_table' => 'impersonator_approval_decisions',
        ];
    }

    /**
     * The configured names, in declaration order.
     *
     * @return list<string>
     */
    public static function names(Settings $settings): array
    {
        $names = [];

        foreach (self::map() as $key => $default) {
            $names[] = $settings->string($key, $default);
        }

        return $names;
    }

    public static function count(): int
    {
        return count(self::map());
    }
}
