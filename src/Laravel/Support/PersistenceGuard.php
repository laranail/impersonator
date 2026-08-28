<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Contracts\ModeEnforcer;
use Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * The armed state behind the persistence-level mode guard.
 *
 * `DB::beforeExecuting` has no counterpart that removes a listener, so a guard registered per
 * request would never come off. Three things go wrong when it does not:
 *
 *  1. **Leaving breaks.** Closing an impersonation is an `UPDATE` on the audit row. A read-only
 *     guard still listening after the response denies it, and the operator is trapped inside the
 *     customer's account — the exact outcome the mode is supposed to be safer than.
 *  2. **Listeners accumulate.** Under Octane, a queue worker, or any process serving more than one
 *     request, every request adds another closure that never leaves.
 *  3. **The session goes stale.** Each closure captures the impersonation that armed it and keeps
 *     enforcing that one, long after it ended.
 *
 * So the listener is registered exactly once, at boot, and consults this object. The middleware
 * arms it for the request and disarms it in a `finally`, which means enforcement is bounded by the
 * request whether it ends in a response or an exception.
 */
final class PersistenceGuard
{
    private ?ImpersonationSession $session = null;

    private ?ModeEnforcer $enforcer = null;

    private string $path = '';

    /** @var list<string> */
    private array $exemptTables = [];

    /** @param list<string> $exemptTables */
    public function arm(
        ImpersonationSession $session,
        ModeEnforcer $enforcer,
        string $path,
        array $exemptTables,
    ): void {
        $this->session = $session;
        $this->enforcer = $enforcer;
        $this->path = $path;
        $this->exemptTables = array_map(strtolower(...), $exemptTables);
    }

    public function disarm(): void
    {
        $this->session = null;
        $this->enforcer = null;
        $this->path = '';
        $this->exemptTables = [];
    }

    public function armed(): bool
    {
        return $this->session !== null && $this->enforcer !== null;
    }

    /**
     * The decision for one statement, or null when there is nothing to decide.
     *
     * Null means "not our business": no impersonation is armed, the statement is a read, or it
     * writes to a table the guard is exempt from.
     */
    public function inspect(string $query): ?Decision
    {
        if ($this->session === null || $this->enforcer === null) {
            return null;
        }

        $operation = $this->writeVerb($query);

        if ($operation === null) {
            return null;
        }

        $table = $this->tableFrom($query);

        if ($table !== null && $this->isExempt($table)) {
            return null;
        }

        return $this->enforcer->check(
            AttemptedAction::write(
                // The unqualified name, because that is what a deny-list or an exempt list is
                // written in. The qualified form is kept only for the report.
                modelClass: $table['table'] ?? 'unknown',
                operation: $operation,
                path: $this->path,
            ),
            $this->session,
        );
    }

    public function session(): ?ImpersonationSession
    {
        return $this->session;
    }

    /**
     * Whether a write to this table is none of the guard's business.
     *
     * Both forms are compared, because a statement may name the table either way and an exempt
     * list may be written either way. Matching only one is how `read_only` came to block Laravel's
     * own session write on PostgreSQL: the statement said `"public"."sessions"`, the exempt list
     * said `sessions`, and nothing lined up.
     *
     * @param array{qualified: string, table: string} $table
     */
    private function isExempt(array $table): bool
    {
        return in_array(strtolower($table['table']), $this->exemptTables, true)
            || in_array(strtolower($table['qualified']), $this->exemptTables, true);
    }

    /**
     * The write verb a statement begins with, or null for a read.
     *
     * Matched on the leading keyword only. Anything that is not plainly a read counts as a write,
     * so an unrecognised statement fails closed.
     */
    private function writeVerb(string $query): ?string
    {
        if (preg_match('/^(insert|update|delete|replace|truncate|drop|alter|create)\b/i', ltrim($query), $m) === 1) {
            return strtolower($m[1]);
        }

        return null;
    }

    /**
     * The table a write targets, in both its qualified and unqualified forms.
     *
     * Every driver quotes differently and any of them may qualify the name — `"public"."sessions"`
     * on PostgreSQL, `` `db`.`sessions` `` on MySQL, `[dbo].[sessions]` on SQL Server, bare on
     * SQLite. So the whole dotted chain is matched, the delimiters are stripped, and the caller gets
     * both: `qualified` for the report and `table` for matching against a configured list.
     *
     * Reading the chain rather than stopping at the first delimiter is the fix for a real defect:
     * the previous pattern returned `public` for `"public"."sessions"`, so the session table never
     * matched its exemption and `read_only` refused every request on PostgreSQL and MySQL. It went
     * unseen because the suite ran SQLite, which emits unqualified names.
     *
     * @return array{qualified: string, table: string}|null
     */
    private function tableFrom(string $query): ?array
    {
        $identifier = '(?:[`"\[]?[\w$]+[`"\]]?)';
        $pattern = '/^\s*(?:insert\s+into|update|delete\s+from|replace\s+into)\s+'
            . '((?:' . $identifier . '\.)*' . $identifier . ')/i';

        if (preg_match($pattern, $query, $m) !== 1) {
            return null;
        }

        $qualified = str_replace(['`', '"', '[', ']'], '', $m[1]);
        $segments = explode('.', $qualified);

        return ['qualified' => $qualified, 'table' => end($segments)];
    }
}
