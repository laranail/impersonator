<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Commands;

use Illuminate\Console\Command;
use Simtabi\Laranail\Impersonator\Core\Support\AuditChain;
use Simtabi\Laranail\Impersonator\Laravel\Audit\EloquentAuditStore;
use Simtabi\Laranail\Impersonator\Laravel\Commands\Concerns\SupportsNamespacedNames;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * Walks the audit chain and reports the first place it breaks.
 *
 * A break means one of three things, and the command cannot tell them apart — which is fine,
 * because all three want the same response: a row was altered, a row was deleted, or a row was
 * inserted after the fact. What it can say precisely is *where* the chain stops verifying, and
 * every row from there on is suspect.
 *
 * Exits non-zero on a break, so it can be a scheduled check rather than something somebody
 * remembers to run.
 */
class VerifyAuditCommand extends Command
{
    protected $description = 'Verify the tamper-evidence chain over the impersonation audit trail';

    use SupportsNamespacedNames;

    public function handle(Settings $settings, EloquentAuditStore $store): int
    {
        if (! $settings->bool('audit.tamper_evident', false)) {
            $this->components->warn(
                'Tamper evidence is off (impersonator.audit.tamper_evident), so there is no chain '
                . 'to verify. Rows written while it was off carry no digest.',
            );

            return self::SUCCESS;
        }

        $key = $settings->nullableString('audit.hash_key');

        if ($key === null) {
            $this->components->error(
                'impersonator.audit.hash_key is not set. Verification needs the same key the rows '
                . 'were written with, and it must live outside the database — a chain whose key is '
                . 'stored alongside the rows protects nothing.',
            );

            return self::FAILURE;
        }

        $chain = new AuditChain($key);
        $expectedPrevious = null;
        $checked = 0;

        // Chronological, matching the order the chain was built in.
        foreach ($this->rows() as $row) {
            $recorded = $row->getAttribute('hash');

            if (! is_string($recorded) || $recorded === '') {
                // Written before tamper evidence was switched on. Skipped rather than failed:
                // reporting a break for rows that never had a digest would make the command
                // useless on every existing installation.
                continue;
            }

            $checked++;

            $facts = $store->chainFactsFromRow($row);

            if (! $chain->verify($facts, $expectedPrevious, $recorded)) {
                $key = $row->getKey();
                $startedAt = $row->getAttribute('started_at');

                $this->components->error(sprintf(
                    'The audit chain breaks at row [%s] (started %s). Every row from here on is '
                    . 'suspect: one was altered, deleted, or inserted after the fact.',
                    is_scalar($key) ? (string) $key : 'unknown',
                    $startedAt instanceof \DateTimeInterface ? $startedAt->format(DATE_ATOM) : 'unknown',
                ));

                return self::FAILURE;
            }

            $expectedPrevious = $recorded;
        }

        $this->components->info(sprintf(
            '%d audit row%s verified. The chain is intact.',
            $checked,
            $checked === 1 ? '' : 's',
        ));

        return self::SUCCESS;
    }

    /** @return iterable<ImpersonationAudit> */
    private function rows(): iterable
    {
        // Chunked, because an audit trail is the one table that only ever grows.
        return ImpersonationAudit::query()
            ->orderBy('started_at')
            ->orderBy('id')
            ->lazy();
    }

    protected function namespacedSignature(): string
    {
        return 'laranail::impersonator.verify-audit';
    }
}
