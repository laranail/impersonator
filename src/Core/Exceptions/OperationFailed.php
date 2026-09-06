<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Exceptions;

use Throwable;
use Simtabi\Laranail\Impersonator\Core\Enums\Criticality;

/**
 * A named operation failed, wrapped with its classification.
 *
 * The original throwable is preserved as `previous`, never flattened into the
 * message: the cause chain and stack trace have to survive, or a report cannot be
 * diagnosed without a reproduction.
 *
 * `context()` satisfies the descriptiveness bar — what operation, expected versus
 * actual, the cause chain, relevant identifiers, and the decision the runner took.
 * Keep it redacted: it carries names and ids only, never a token, credential or
 * anything personal, because failure paths are exactly where raw input tends to
 * get dumped.
 */
final class OperationFailed extends ImpersonationException
{
    /** @param array<string, mixed> $identifiers */
    private function __construct(
        public readonly string $operation,
        public readonly Criticality $criticality,
        public readonly ?string $expected,
        private readonly array $identifiers,
        Throwable $previous,
    ) {
        parent::__construct(
            sprintf('Impersonator operation [%s] failed: %s', $operation, $previous->getMessage()),
            previous: $previous,
        );
    }

    /** @param array<string, mixed> $identifiers */
    public static function from(
        string $operation,
        Criticality $criticality,
        Throwable $previous,
        ?string $expected = null,
        array $identifiers = [],
    ): self {
        return new self($operation, $criticality, $expected, $identifiers, $previous);
    }

    /** @return array<string, mixed> */
    public function context(): array
    {
        $previous = $this->getPrevious();

        return array_filter([
            'operation'   => $this->operation,
            'criticality' => $this->criticality->name,
            'decision'    => $this->criticality->decision(),
            'expected'    => $this->expected,
            'actual'      => $previous?->getMessage(),
            'cause_type'  => $previous === null ? null : $previous::class,
            'identifiers' => $this->identifiers,
        ], static fn (mixed $value): bool => $value !== null && $value !== []);
    }
}
