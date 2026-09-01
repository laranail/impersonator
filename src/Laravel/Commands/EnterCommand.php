<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;
use Simtabi\Laranail\Impersonator\Laravel\Commands\Concerns\SupportsNamespacedNames;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Services\ImpersonationService;
use Simtabi\Laranail\Impersonator\Laravel\Support\TargetRegistry;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Starts an impersonation from the CLI and prints a one-time accept URL.
 *
 * For a support engineer working from a shell — an on-call escalation, a customer report that
 * needs looking at before anyone builds a UI for it. The authorization stack is the same one the
 * HTTP endpoint uses; nothing here bypasses it, and `--as` is required precisely so the audit row
 * names a real operator rather than "the console".
 *
 * **The printed URL is a live credential.** It is single-use and short-lived, but between being
 * printed and being followed it is enough to enter somebody's account — and a terminal is a place
 * where output gets scrolled back, screen-shared and captured by CI logs. The command says so
 * rather than printing it silently, and it is deliberately never written to the package's own log.
 */
class EnterCommand extends Command
{
    use SupportsNamespacedNames;

    protected $description = 'Start an impersonation and print a one-time accept URL';

    public function handle(
        ImpersonationService $impersonations,
        ImpersonationManager $manager,
        TargetRegistry $targets,
    ): int {
        $operator = $this->resolve($targets, $this->stringOption('as') ?? '', '--as');
        $target = $this->resolve($targets, $this->stringArgument('user'), 'user');

        if ($operator === null || $target === null) {
            return self::FAILURE;
        }

        try {
            $outcome = $impersonations->enter(
                target: $target,
                mode: $this->stringOption('mode'),
                reason: $this->stringOption('reason'),
                impersonator: $operator,
                // Recorded so an audit reader can tell a console-initiated impersonation from one
                // started through the UI — they warrant different scrutiny.
                metadata: ['entered_via' => 'console'],
            );
        } catch (ImpersonationDenied $denied) {
            $this->components->error(sprintf('Refused (%s): %s', $denied->code(), $denied->getMessage()));

            return self::FAILURE;
        } catch (ImpersonationException $failure) {
            $this->components->error($failure->getMessage());

            return self::FAILURE;
        }

        $this->components->info(sprintf('Impersonation opened as audit row %s.', $outcome->auditId()));

        if (! $outcome->pending) {
            // A same-app driver has already authenticated somebody — in this process, which ends
            // in a moment. Saying so avoids the operator waiting for a URL that is not coming.
            $this->components->warn(
                'This driver completes in-process, so there is no accept URL. Configure the token '
                .'or tenancy driver to hand an operator a link they can follow.',
            );

            return self::SUCCESS;
        }

        $this->newLine();
        $this->components->warn(
            'The URL below is a live single-use credential. It expires shortly, but until it is '
            .'used or expires anyone holding it can enter this account. Do not paste it into a '
            .'ticket, a chat, or anywhere it will be stored.',
        );
        $this->newLine();
        $this->output->writeln($outcome->acceptUrl(), OutputInterface::OUTPUT_RAW);
        $this->newLine();

        return self::SUCCESS;
    }

    protected function namespacedSignature(): string
    {
        return 'laranail::impersonator.enter
            {user : the target, as type:id or a bare id when only one type is registered}
            {--as= : the operator to record as the impersonator, as type:id or a bare id}
            {--mode= : impersonation mode; defaults to impersonator.default_mode}
            {--reason= : why, recorded on the audit row}';
    }

    /**
     * Resolve `type:id` or a bare id against the registered target types.
     *
     * A bare id is accepted only when exactly one type is registered — with several, guessing which
     * one was meant could enter the wrong account entirely, so it asks instead.
     */
    private function resolve(TargetRegistry $targets, string $reference, string $label): ?Model
    {
        if ($reference === '') {
            $this->components->error(sprintf('%s is required.', $label));

            return null;
        }

        $identities = app(ImpersonationManager::class)->identities();

        if (str_contains($reference, ':')) {
            [$type, $id] = explode(':', $reference, 2);
        } else {
            $aliases = $targets->aliases();

            if (count($aliases) !== 1) {
                $this->components->error(__('laranail-impersonator::console.enter.ambiguous', [
                    'subject' => $label,
                    'value' => $reference,
                    'count' => count($aliases),
                    'types' => implode(', ', $aliases) ?: 'none',
                ]));

                return null;
            }

            $type = $aliases[0];
            $id = $reference;
        }

        $model = $identities->resolveActor($identities->identity($type, $id));

        if ($model === null) {
            $this->components->error(sprintf('No %s found for [%s:%s].', $label, $type, $id));
        }

        return $model;
    }
}
