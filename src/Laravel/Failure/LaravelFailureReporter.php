<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Failure;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Log\LogManager;
use Simtabi\Laranail\Impersonator\Core\Contracts\FailureReporter;
use Simtabi\Laranail\Impersonator\Core\Exceptions\OperationFailed;
use Throwable;

/**
 * Routes handled failures to Laravel's central exception handler, which is what
 * carries them on to Sentry, Flare, Bugsnag or whatever is configured.
 *
 * Writing to a log file and continuing would not satisfy the standard: "loud" means
 * the monitoring pipeline, not a line somebody has to go looking for.
 *
 * Every path here is guarded. This class is the reporting substrate, so it cannot
 * report its own failures through itself without infinite regress — it falls back to
 * `error_log()`, which is the documented last resort, and never throws. A broken
 * monitoring integration must not turn a degradable failure into a crash.
 */
final readonly class LaravelFailureReporter implements FailureReporter
{
    public function __construct(
        private ExceptionHandler $handler,
        private LogManager $logs,
    ) {}

    public function report(Throwable $failure): void
    {
        try {
            // Structured context first, so the record carries what/expected/actual/
            // decision even for handlers that only forward the message. The cause
            // chain survives on the exception itself via `previous`.
            if ($failure instanceof OperationFailed) {
                $this->logs->error($failure->getMessage(), $failure->context());
            }

            $this->handler->report($failure);
        } catch (Throwable $reportingFailure) {
            $this->lastResort($failure);
            $this->lastResort($reportingFailure);
        }
    }

    public function warn(string $message, array $context = []): void
    {
        try {
            $this->logs->warning($message, $context);
        } catch (Throwable $reportingFailure) {
            $this->lastResort($reportingFailure);
        }
    }

    /**
     * The floor beneath the reporting stack. `error_log` is chosen because it needs
     * no container, no configured channel and no filesystem the app owns — the three
     * things most likely to be the reason reporting failed in the first place.
     */
    private function lastResort(Throwable $failure): void
    {
        error_log(sprintf(
            '[impersonator] %s: %s in %s:%d',
            $failure::class,
            $failure->getMessage(),
            $failure->getFile(),
            $failure->getLine(),
        ));
    }
}
