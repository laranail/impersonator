<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Support;

use Simtabi\Laranail\Impersonator\Core\Contracts\FailureReporter;
use Simtabi\Laranail\Impersonator\Core\Enums\Criticality;
use Simtabi\Laranail\Impersonator\Core\Exceptions\OperationFailed;
use Throwable;

/**
 * The one runner that applies the failure classification uniformly.
 *
 * Its shape is normative: classify, report through the central handler with the
 * report itself guarded, crash on critical, record-and-continue on degradable. No
 * environment check appears anywhere in this path — that is the entire point. What
 * the test suite exercises is what production runs.
 *
 * Operations are run in the order given, and callers order them critical-first, so
 * a degradable failure never leaves a later operation depending on a capability
 * that was silently dropped.
 */
final readonly class FailurePolicy
{
    public function __construct(
        private FailureReporter $reporter,
        private FailureReport $report,
    ) {}

    /**
     * Run one classified operation.
     *
     * @template T
     *
     * @param callable(): T $operation
     * @param array<string, mixed> $identifiers redacted; names and ids only
     * @return T|null the operation's value, or null when a degradable one failed
     *
     * @throws OperationFailed when a critical operation fails
     */
    public function run(
        string $name,
        Criticality $criticality,
        callable $operation,
        ?string $expected = null,
        array $identifiers = [],
    ): mixed {
        try {
            return $operation();
        } catch (Throwable $original) {
            $wrapped = OperationFailed::from($name, $criticality, $original, $expected, $identifiers);

            $this->reporter->report($wrapped);

            if ($criticality === Criticality::Critical) {
                // Fail fast, at the point the invalid state was detected, and
                // identically in every environment.
                throw $wrapped;
            }

            $this->report->recordDegraded($name, $original);

            return null;
        }
    }

    /**
     * Run an operation whose failure is unsafe to continue past.
     *
     * @template T
     *
     * @param callable(): T $operation
     * @param array<string, mixed> $identifiers
     * @return T
     */
    public function critical(
        string $name,
        callable $operation,
        ?string $expected = null,
        array $identifiers = [],
    ): mixed {
        /** @var T */
        return $this->run($name, Criticality::Critical, $operation, $expected, $identifiers);
    }

    /**
     * Run an operation whose failure leaves a safe, reduced state.
     *
     * Declaring something degradable is an explicit, reviewable decision — an
     * unclassified failure defaults to critical, so this is never the fallback for
     * "I did not think about it".
     *
     * @template T
     *
     * @param callable(): T $operation
     * @param array<string, mixed> $identifiers
     * @return T|null
     */
    public function degradable(
        string $name,
        callable $operation,
        ?string $expected = null,
        array $identifiers = [],
    ): mixed {
        return $this->run($name, Criticality::Degradable, $operation, $expected, $identifiers);
    }

    /**
     * Log a tolerated anomaly: a fallback fired, a value was out of range but
     * accepted. Not a failure, so it never reaches the catch path above.
     *
     * @param array<string, mixed> $identifiers
     */
    public function warn(string $operation, string $expected, string $actual, array $identifiers = []): void
    {
        $this->reporter->warn(sprintf('Impersonator: %s used a fallback.', $operation), [
            'operation' => $operation,
            'expected' => $expected,
            'actual' => $actual,
            'decision' => 'tolerated',
            'identifiers' => $identifiers,
        ]);
    }

    public function report(): FailureReport
    {
        return $this->report;
    }
}
