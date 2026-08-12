<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Commands;

use Illuminate\Console\Command;
use Simtabi\Laranail\Impersonator\Laravel\Commands\Concerns\SupportsNamespacedNames;
use Simtabi\Laranail\Impersonator\Laravel\Services\ApprovalService;

/**
 * Expires break-glass requests nobody answered.
 *
 * Not a security boundary — expiry is enforced when a permit is read, so a stale request is
 * already dead whether or not this has run. What scheduling it adds is the *notification*: this
 * is what tells a waiting operator that nobody replied, which is the difference between them
 * knowing to escalate and them assuming the system is broken.
 *
 * Note this expires rather than deletes. Removing the record that somebody asked for access to
 * an account is exactly what an auditor came to read; deletion is `model:prune`'s job, and only
 * past `approval.retention_days`.
 */
class PruneApprovalsCommand extends Command
{
    use SupportsNamespacedNames;

    protected function namespacedSignature(): string
    {
        return 'laranail::impersonator.prune-approvals {--limit=500 : Maximum requests to expire in one pass}';
    }

    protected $description = 'Expire impersonation approval requests that were never decided';

    public function handle(ApprovalService $approvals): int
    {
        $limit = (int) $this->option('limit');

        $expired = $approvals->expireStale($limit > 0 ? $limit : 500);

        if ($expired === []) {
            $this->components->info('No impersonation approval requests needed expiring.');

            return self::SUCCESS;
        }

        foreach ($expired as $request) {
            $this->components->twoColumnDetail(
                $request->id,
                sprintf(
                    '%s → %s (%s)',
                    $request->requester->label ?? $request->requester->key(),
                    $request->target->label ?? $request->target->key(),
                    $request->mode->name,
                ),
            );
        }

        // `trans_choice`, not a `request%s` splice. Appending an `s` is only right in a language that
        // pluralises like English, and the shape of a counted sentence is exactly what a locale changes.
        $this->components->info(trans_choice(
            'impersonator::console.prune_approvals.expired',
            count($expired),
            ['count' => count($expired)],
        ));

        return self::SUCCESS;
    }
}
