<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Container\Container;
use Simtabi\Laranail\Impersonator\Laravel\Commands\Concerns\SupportsNamespacedNames;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorStatus;
use Throwable;

/**
 * Checks the things that are wrong silently.
 *
 * Every check exists because the failure it catches produces no error — impersonation appears to
 * work, and the gap only surfaces during an incident or an audit. A missing table throws on first use
 * and needs no doctor; an operator who can enter but not choose a mode, or a revocation switch that
 * cannot actually end a session, will pass every smoke test.
 *
 * Three severities, and the distinction is what makes the output worth reading:
 *
 *  - **fail** — impersonation is broken or a control is not enforcing. Exits non-zero.
 *  - **warn** — it works, but a control is weaker than the configuration implies.
 *  - **pass** — checked and sound.
 *
 * `skip` also appears, for a check whose precondition is absent — approver notifications when
 * approval is not required. Reported rather than hidden, because "not applicable" and "not checked"
 * are different statements and only one of them is reassuring.
 *
 * Exits non-zero only on a failure, so it can run in CI as a gate rather than as advice.
 *
 * **A runner, not a container.** The checks are {@see Checks} objects shared with the family-wide
 * `laranail::package-tools.doctor`, so running either reports the same findings. This command stays
 * because it is documented, tested and referenced from the issue template — and because it exits
 * non-zero, which is what makes it usable as a gate.
 */
class DoctorCommand extends Command
{
    use SupportsNamespacedNames;

    protected $description = 'Diagnose the impersonation configuration and report what is silently wrong';

    protected function namespacedSignature(): string
    {
        return 'laranail::impersonator.doctor';
    }

    public function handle(Container $container): int
    {
        $this->components->info(__('laranail-impersonator::console.doctor.heading'));

        $failures = 0;
        $warnings = 0;

        foreach (Checks::all() as $class) {
            [$label, $result] = $this->runCheck($container, $class);

            $this->report($label, $result);

            $result->status === DoctorStatus::Fail && $failures++;
            $result->status === DoctorStatus::Warn && $warnings++;
        }

        $this->newLine();

        if ($failures > 0) {
            // Counted on failures, since that is the number the sentence turns on.
            $this->components->error(trans_choice(
                'laranail-impersonator::console.doctor.failed',
                $failures,
                [
                    'failures' => $failures,
                    'warnings' => trans_choice(
                        'laranail-impersonator::console.doctor.warning_count',
                        $warnings,
                        ['count' => $warnings],
                    ),
                ],
            ));

            return self::FAILURE;
        }

        // Warnings do not fail the command. Several are legitimate choices — an unlimited duration on
        // an internal tool, tamper evidence off where the trail is not evidence — and a doctor that
        // exits non-zero for a deliberate decision is one teams stop running.
        $warnings > 0
            ? $this->components->warn(trans_choice(
                'laranail-impersonator::console.doctor.warnings',
                $warnings,
                ['count' => $warnings],
            ))
            : $this->components->info(__('laranail-impersonator::console.doctor.clean'));

        return self::SUCCESS;
    }

    /**
     * Build and run one check, surviving both.
     *
     * The `DoctorCheck` contract says `run()` never throws and {@see Check} upholds it — but this
     * command is the thing somebody runs *because* the install is broken, so it does not take that on
     * trust. A check that throws anyway is reported as a failure of that check; the remaining
     * eighteen still run, which is the whole reason to diagnose rather than crash.
     *
     * @param class-string<Check> $class
     * @return array{0: string, 1: DoctorResult}
     */
    private function runCheck(Container $container, string $class): array
    {
        try {
            $check = $container->make($class);

            // Verified rather than assumed. `make()` is `mixed` to static analysis, and it is also
            // genuinely overridable — a host application may rebind any of these — so a binding
            // returning something else is reported instead of reaching for a method that is not there.
            if (! $check instanceof Check) {
                return [
                    class_basename($class),
                    DoctorResult::fail(__('laranail-impersonator::console.doctor.wrong_type', [
                        'type' => get_debug_type($check),
                        'expected' => Check::class,
                    ])),
                ];
            }

            return [$check->name(), $check->run()];
        } catch (Throwable $e) {
            return [
                class_basename($class),
                DoctorResult::fail(__('laranail-impersonator::console.doctor.check_failed', ['message' => $e->getMessage()])),
            ];
        }
    }

    private function report(string $label, DoctorResult $result): void
    {
        $tag = match ($result->status) {
            DoctorStatus::Fail => '<fg=red>FAIL</>',
            DoctorStatus::Warn => '<fg=yellow>WARN</>',
            DoctorStatus::Skip => '<fg=gray>SKIP</>',
            DoctorStatus::Pass => '<fg=green>OK</>',
        };

        $this->components->twoColumnDetail(sprintf('%s  %s', $tag, $label), '');
        $this->line('       ' . $result->message);
    }
}
