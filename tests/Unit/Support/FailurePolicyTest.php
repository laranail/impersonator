<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Enums\Criticality;
use Simtabi\Laranail\Impersonator\Core\Support\FailurePolicy;
use Simtabi\Laranail\Impersonator\Core\Support\FailureReport;
use Simtabi\Laranail\Impersonator\Core\Contracts\FailureReporter;
use Simtabi\Laranail\Impersonator\Core\Exceptions\OperationFailed;

/**
 * The failure-handling standard's own tests. A fake reporter is used throughout, so
 * these assert what was reported without reaching live monitoring.
 */
function fakeReporter(bool $throwOnReport = false): FailureReporter
{
    return new class($throwOnReport) implements FailureReporter
    {
        /** @var list<Throwable> */
        public array $reported = [];

        /** @var list<array{message: string, context: array<string, mixed>}> */
        public array $warnings = [];

        public function __construct(private readonly bool $throwOnReport) {}

        public function report(Throwable $failure): void
        {
            if ($this->throwOnReport) {
                throw new RuntimeException('monitoring is down');
            }

            $this->reported[] = $failure;
        }

        public function warn(string $message, array $context = []): void
        {
            $this->warnings[] = ['message' => $message, 'context' => $context];
        }
    };
}

function failurePolicy(FailureReporter $reporter, ?FailureReport $report = null): FailurePolicy
{
    return new FailurePolicy($reporter, $report ?? new FailureReport);
}

it('returns the value of an operation that succeeds', function (): void {
    expect(failurePolicy(fakeReporter())->critical('op', static fn (): string => 'value'))->toBe('value');
});

it('reports nothing when nothing fails', function (): void {
    $reporter = fakeReporter();
    failurePolicy($reporter)->degradable('op', static fn (): bool => true);

    expect($reporter->reported)->toBe([]);
});

it('crashes on a critical failure', function (): void {
    failurePolicy(fakeReporter())->critical('op.critical', static fn () => throw new RuntimeException('boom'));
})->throws(OperationFailed::class);

it('reports a critical failure before crashing', function (): void {
    $reporter = fakeReporter();

    try {
        failurePolicy($reporter)->critical('op.critical', static fn () => throw new RuntimeException('boom'));
    } catch (OperationFailed) {
        // expected
    }

    expect($reporter->reported)->toHaveCount(1);
});

it('continues past a degradable failure', function (): void {
    $reporter = fakeReporter();

    expect(failurePolicy($reporter)->degradable('op.soft', static fn () => throw new RuntimeException('boom')))
        ->toBeNull()
        ->and($reporter->reported)->toHaveCount(1);
});

it('records degraded state so it is observable, not just paged', function (): void {
    $report = new FailureReport;

    failurePolicy(fakeReporter(), $report)->degradable('op.soft', static fn () => throw new RuntimeException('boom'));

    expect($report->isHealthy())->toBeFalse()
        ->and($report->isDegraded('op.soft'))->toBeTrue()
        ->and($report->degradedOperations())->toBe(['op.soft']);
});

it('does not record degraded state for a critical failure', function (): void {
    // A critical failure crashed, so there is no reduced state to keep serving.
    $report = new FailureReport;

    try {
        failurePolicy(fakeReporter(), $report)->critical('op', static fn () => throw new RuntimeException('boom'));
    } catch (OperationFailed) {
        // expected
    }

    expect($report->isHealthy())->toBeTrue();
});

it('keeps the first cause when an operation fails repeatedly', function (): void {
    // A later, shallower error must not overwrite the original cause of a capability
    // that has been down since boot.
    $report = new FailureReport;
    $policy = failurePolicy(fakeReporter(), $report);

    $policy->degradable('op', static fn () => throw new RuntimeException('original'));
    $policy->degradable('op', static fn () => throw new RuntimeException('later'));

    expect($report->degraded()['op']['message'])->toBe('original');
});

it('preserves the cause chain rather than flattening it to a string', function (): void {
    $original = new RuntimeException('root cause');
    $reporter = fakeReporter();

    try {
        failurePolicy($reporter)->critical('op', static fn () => throw $original);
    } catch (OperationFailed) {
        // expected
    }

    expect($reporter->reported[0]->getPrevious())->toBe($original);
});

it('carries descriptive structured context', function (): void {
    $reporter = fakeReporter();

    try {
        failurePolicy($reporter)->critical(
            'impersonator.boot.gates',
            static fn () => throw new RuntimeException('gate blew up'),
            expected: 'the impersonation gates to register',
            identifiers: ['ability' => 'impersonator.revoke'],
        );
    } catch (OperationFailed) {
        // expected
    }

    $context = $reporter->reported[0]->context();

    expect($context['operation'])->toBe('impersonator.boot.gates')
        ->and($context['criticality'])->toBe('Critical')
        ->and($context['decision'])->toBe('crashed')
        ->and($context['expected'])->toBe('the impersonation gates to register')
        ->and($context['actual'])->toBe('gate blew up')
        ->and($context['cause_type'])->toBe(RuntimeException::class)
        ->and($context['identifiers'])->toBe(['ability' => 'impersonator.revoke']);
});

it('labels a degradable decision as degraded-and-continued', function (): void {
    $reporter = fakeReporter();
    failurePolicy($reporter)->degradable('op', static fn () => throw new RuntimeException('x'));

    expect($reporter->reported[0]->context()['decision'])->toBe('degraded-and-continued');
});

it('logs a tolerated anomaly as a warning rather than a failure', function (): void {
    // Severity has to match reality: a fallback that fired and a real failure must not
    // log at the same level.
    $reporter = fakeReporter();

    failurePolicy($reporter)->warn('mode resolution', 'a registered mode', 'unknown, used the default');

    expect($reporter->reported)->toBe([])
        ->and($reporter->warnings)->toHaveCount(1)
        ->and($reporter->warnings[0]['context']['decision'])->toBe('tolerated')
        ->and($reporter->warnings[0]['context']['expected'])->toBe('a registered mode');
});

it('treats criticality as the only lever, with no environment input', function (): void {
    // Behaviour is keyed on consequence. There is deliberately no flag, override or
    // environment check that could downgrade a critical failure.
    expect(Criticality::Critical->decision())->toBe('crashed')
        ->and(Criticality::Degradable->decision())->toBe('degraded-and-continued')
        ->and(Criticality::cases())->toHaveCount(2);
});

it('starts healthy and can be flushed', function (): void {
    $report = new FailureReport;

    expect($report->isHealthy())->toBeTrue();

    failurePolicy(fakeReporter(), $report)->degradable('op', static fn () => throw new RuntimeException('x'));
    expect($report->isHealthy())->toBeFalse();

    $report->flush();
    expect($report->isHealthy())->toBeTrue();
});

it('reports a repeating degradable failure once, not once per call', function (): void {
    // Rule 9 of the failure-handling standard, previously unimplemented. A degradable operation invoked
    // per request and failing every time emitted a line per request — which buries the *other* failures,
    // and turns one broken capability into a page storm on a reporter wired to notifications.
    $reporter = fakeReporter();
    $report = new FailureReport;
    $policy = failurePolicy($reporter, $report);

    for ($i = 0; $i < 5; $i++) {
        $policy->degradable('impersonator.boot.routes', static function (): never {
            throw new RuntimeException('routes are broken');
        });
    }

    expect($reporter->reported)->toHaveCount(1)
        // Recorded every time regardless: the *state* is what a health probe reads, and it must not
        // depend on whether the line was throttled.
        ->and($report->isDegraded('impersonator.boot.routes'))->toBeTrue()
        ->and($report->isHealthy())->toBeFalse();
});

it('throttles per operation, so one noisy failure does not mask another', function (): void {
    $reporter = fakeReporter();
    $policy = failurePolicy($reporter, $report = new FailureReport);

    foreach (['routes', 'views', 'routes', 'views', 'listeners'] as $operation) {
        $policy->degradable($operation, static function (): never {
            throw new RuntimeException('broken');
        });
    }

    // Three distinct operations, three lines — not one, and not five.
    expect($reporter->reported)->toHaveCount(3)
        ->and($report->degradedOperations())->toHaveCount(3);
});

it('reports again after a flush, because that is a new lifecycle', function (): void {
    // Under Octane or a queue worker the report is flushed per request. A failure in the next request
    // is news again — suppressing it forever would make a persistent fault invisible after the first.
    $reporter = fakeReporter();
    $policy = failurePolicy($reporter, $report = new FailureReport);

    $fail = static function (): never {
        throw new RuntimeException('broken');
    };

    $policy->degradable('op', $fail);
    $policy->degradable('op', $fail);
    $report->flush();
    $policy->degradable('op', $fail);

    expect($reporter->reported)->toHaveCount(2);
});

it('always reports a critical failure, which happens once by definition', function (): void {
    // Nothing continues past a critical failure, so there is nothing to throttle — and suppressing one
    // would be the worst possible trade.
    $reporter = fakeReporter();
    $policy = failurePolicy($reporter, new FailureReport);

    foreach (range(1, 3) as $ignored) {
        try {
            $policy->critical('op', static function (): never {
                throw new RuntimeException('fatal');
            });
        } catch (OperationFailed) {
            // expected
        }
    }

    expect($reporter->reported)->toHaveCount(3);
});
