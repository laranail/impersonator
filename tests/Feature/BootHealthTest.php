<?php

declare(strict_types=1);

use Illuminate\Contracts\Debug\ExceptionHandler;
use Simtabi\Laranail\Impersonator\Core\Contracts\FailureReporter;
use Simtabi\Laranail\Impersonator\Core\Support\FailureReport;
use Simtabi\Laranail\Impersonator\Laravel\Failure\LaravelFailureReporter;

/**
 * The CI gate required by rule 12 of the failure-handling standard.
 *
 * Asserting the boot report is healthy after an ordinary boot is what catches a broken
 * degradable operation — the kind that would otherwise pass silently, since by
 * definition it does not crash. Without this the suite would be green while the banner,
 * the routes or the listeners had quietly failed to register.
 */
it('boots healthy, with nothing degraded', function (): void {
    $report = app(FailureReport::class);

    expect($report->isHealthy())->toBeTrue(
        'the package booted degraded: '.json_encode($report->degraded()),
    );
});

it('shares one boot report across the application', function (): void {
    // A paged report is not a queryable state; the doctor command, a health route and
    // this gate all have to read the same facts.
    expect(app(FailureReport::class))->toBe(app(FailureReport::class));
});

it('binds a reporter that routes to the central handler', function (): void {
    expect(app(FailureReporter::class))->toBeInstanceOf(LaravelFailureReporter::class);
});

it('never throws out of the reporter, even when the handler does', function (): void {
    // The reporting substrate cannot report through itself; it falls back to a
    // last-resort local write. A broken monitoring integration must not escalate a
    // degradable failure into a crash.
    $handler = new class implements ExceptionHandler
    {
        public function report(Throwable $e): void
        {
            throw new RuntimeException('monitoring is down');
        }

        public function shouldReport(Throwable $e): bool
        {
            return true;
        }

        public function render($request, Throwable $e): mixed
        {
            return null;
        }

        public function renderForConsole($output, Throwable $e): void {}
    };

    $reporter = new LaravelFailureReporter($handler, app('log'));

    $reporter->report(new RuntimeException('the original failure'));

    expect(true)->toBeTrue();
});

it('never throws out of a warning either', function (): void {
    $reporter = app(FailureReporter::class);

    $reporter->warn('a tolerated anomaly', ['expected' => 'x', 'actual' => 'y', 'decision' => 'tolerated']);

    expect(true)->toBeTrue();
});
