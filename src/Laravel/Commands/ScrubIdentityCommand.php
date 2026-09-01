<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Commands;

use Illuminate\Console\Command;
use Simtabi\Laranail\Impersonator\Laravel\Commands\Concerns\SupportsNamespacedNames;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationApprovalRequest;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;

/**
 * Removes a person's name from the audit trail without removing the trail.
 *
 * `impersonator_label` and `target_label` are **denormalised PII, deliberately**: an audit row has to
 * stay readable after a rename or a deletion, and a compliance export that resolves names by joining
 live tables reports today's names against yesterday's actions — or nothing at all once the row is
 * gone. That design is right, and it means a GDPR erasure request otherwise leaves the customer's name
 * in the trail with only time-based retention to clear it.
 *
 * So this nulls the labels for one identity and leaves everything else intact: the row, its ids, its
 * timestamps, and **the HMAC chain**. The chain covers the immutable opening facts — impersonator and
 * target *keys*, mode, driver, adapter, guards, tenant, reason, start time — and the labels are not
 * among them, so `verify-audit` still passes afterwards. That was checked rather than assumed, and a
 * test asserts it.
 *
 * What this deliberately does **not** do is delete rows. Erasure of personal data does not extend to
 * erasing the record that a support engineer accessed an account: that record is the controller's own
 * evidence of processing, and destroying it on request would remove the very accountability the trail
 * exists to provide.
 */
class ScrubIdentityCommand extends Command
{
    use SupportsNamespacedNames;

    protected $description = 'Null the denormalised name of one identity across the audit trail, keeping the rows';

    public function handle(): int
    {
        $argument = $this->argument('identity');
        $reference = is_string($argument) ? $argument : '';

        if (! str_contains($reference, ':')) {
            $this->components->error(__('laranail-impersonator::console.scrub_identity.malformed'));

            return self::FAILURE;
        }

        [$type, $id] = explode(':', $reference, 2);
        $dryRun = (bool) $this->option('dry-run');

        $audits = ImpersonationAudit::query()
            ->where(function ($query) use ($type, $id): void {
                $query->where(function ($q) use ($type, $id): void {
                    $q->where('impersonator_type', $type)->where('impersonator_id', $id);
                })->orWhere(function ($q) use ($type, $id): void {
                    $q->where('impersonatable_type', $type)->where('impersonatable_id', $id);
                });
            });

        $matched = $audits->count();

        if ($matched === 0) {
            $this->components->info(__('laranail-impersonator::console.scrub_identity.no_rows'));

            return self::SUCCESS;
        }

        if ($dryRun) {
            $this->components->warn(trans_choice(
                'laranail-impersonator::console.scrub_identity.dry_run',
                $matched,
                ['count' => $matched],
            ));

            return self::SUCCESS;
        }

        // Two updates rather than one, because a row may hold this identity in either column — and in
        // both, when somebody impersonated themselves through a second model. Nulling only the side
        // matched would leave the name behind on the other.
        ImpersonationAudit::query()
            ->where('impersonator_type', $type)
            ->where('impersonator_id', $id)
            ->update(['impersonator_label' => null]);

        ImpersonationAudit::query()
            ->where('impersonatable_type', $type)
            ->where('impersonatable_id', $id)
            ->update(['target_label' => null]);

        $this->components->info(trans_choice(
            'laranail-impersonator::console.scrub_identity.scrubbed',
            $matched,
            ['count' => $matched],
        ));

        // Approvals carry no labels of their own — they store identities as morph pairs and the
        // requester's name is never denormalised there — so nothing to scrub. Reported so an operator
        // running this for a compliance request does not have to wonder.
        $approvals = ImpersonationApprovalRequest::query()
            ->where(function ($query) use ($type, $id): void {
                $query->where(function ($q) use ($type, $id): void {
                    $q->where('requester_type', $type)->where('requester_id', $id);
                })->orWhere(function ($q) use ($type, $id): void {
                    $q->where('impersonatable_type', $type)->where('impersonatable_id', $id);
                });
            })
            ->count();

        $this->components->info(trans_choice(
            'laranail-impersonator::console.scrub_identity.approvals',
            $approvals,
            ['count' => $approvals],
        ));

        return self::SUCCESS;
    }

    protected function namespacedSignature(): string
    {
        return 'laranail::impersonator.scrub-identity
            {identity : The identity to scrub, as type:id — for example user:9902}
            {--dry-run : Report what would change without writing}';
    }
}
