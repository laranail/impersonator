<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Commands;

use Illuminate\Console\Command;
use Simtabi\Laranail\Impersonator\Core\Contracts\TokenRepository;
use Simtabi\Laranail\Impersonator\Laravel\Commands\Concerns\SupportsNamespacedNames;

/**
 * Removes handoff tokens that can no longer be redeemed.
 *
 * Worth scheduling rather than leaving: the table takes a row per enter on the token driver
 * and is read on the hot path of every redemption, so it should stay small. Nothing is lost
 * by pruning — a spent token is not a credential, and the audit row is where the record of
 * the handoff actually lives.
 */
class PruneTokensCommand extends Command
{
    use SupportsNamespacedNames;

    protected function namespacedSignature(): string
    {
        return 'laranail::impersonator.prune-tokens';
    }

    protected $description = 'Delete expired, spent and revoked impersonation handoff tokens';

    public function handle(TokenRepository $tokens): int
    {
        $removed = $tokens->pruneExpired();

        $this->components->info(trans_choice(
            'impersonator::console.prune_tokens.pruned',
            $removed,
            ['count' => $removed],
        ));

        return self::SUCCESS;
    }
}
