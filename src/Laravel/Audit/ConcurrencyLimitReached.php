<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Audit;

use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;

/**
 * A concurrency cap was hit inside the store's locked transaction.
 *
 * The policy checks the same limits earlier and refuses with a Decision, which is what
 * a caller normally sees. This exists for the case the policy cannot cover: two
 * simultaneous requests both passing that check, then both trying to insert. The
 * transaction resolves that race, and this is how the loser finds out.
 *
 * It carries the equivalent Decision so an HTTP layer can render the same refusal as
 * the ordinary path rather than a 500.
 */
final class ConcurrencyLimitReached extends ImpersonationException
{
    private function __construct(
        public readonly Decision $decision,
    ) {
        parent::__construct($decision->reason ?? 'Impersonation concurrency limit reached.');
    }

    public static function forImpersonator(int $active, int $max): self
    {
        return new self(Decision::deny(
            Decision::CONCURRENCY_LIMIT,
            sprintf('You are at your limit of %d concurrent impersonations.', $active),
            ['count' => $active, 'active' => $active, 'max' => $max],
        ));
    }

    public static function targetBusy(string $target): self
    {
        return new self(Decision::deny(
            Decision::TARGET_BUSY,
            'Somebody else is already impersonating that account.',
            ['target' => $target],
        ));
    }
}
