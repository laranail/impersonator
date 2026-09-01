<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Illuminate\Support\Str;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

/**
 * The target allowlist, checked against what actually resolved.
 *
 * Compares the raw config to the registry rather than iterating the registry, because the registry
 * **silently drops** any entry that is not an installed Eloquent model — a typo or a renamed class
 * narrows the allowlist instead of raising anything. Iterating the resolved types would therefore
 * never see the problem: the broken entry is precisely the one that is missing.
 *
 * An empty allowlist is a failure rather than a warning. It is not a permissive default; it refuses
 * every impersonation, with a message about the target type that reads like a bug in the caller.
 */
final class TargetsCheck extends Check
{
    public function name(): string
    {
        return 'Targets';
    }

    public function description(): string
    {
        return 'Whether the impersonatable allowlist resolved everything it was given.';
    }

    public function run(): DoctorResult
    {
        $manager = $this->resolve(ImpersonationManager::class);

        if ($manager === null) {
            return DoctorResult::fail(
                'The impersonation manager could not be built, so the allowlist could not be checked.',
            );
        }

        return $this->safely(function () use ($manager): DoctorResult {
            $types = $manager->targets()->all();
            $dropped = [];

            foreach ($this->settings->array('targets.allowlist') as $alias => $entry) {
                $model = is_array($entry) ? ($entry['model'] ?? null) : $entry;
                $key = is_string($alias) ? $alias : (is_string($model) ? $model : 'unknown');

                if (! array_key_exists($key, $types)) {
                    $dropped[] = sprintf('%s => %s', $key, is_string($model) ? $model : get_debug_type($model));
                }
            }

            if ($dropped !== []) {
                return DoctorResult::fail(
                    sprintf(
                        'Dropped from the allowlist because they are not installed Eloquent models: %s. '
                        .'These were silently ignored, so an enter against them is refused as a '
                        .'non-allowlisted target.',
                        implode(', ', $dropped),
                    ),
                    ['dropped' => $dropped],
                );
            }

            return $types === []
                ? DoctorResult::fail(
                    'impersonator.targets.allowlist is empty, so every enter is refused as a '
                    .'non-allowlisted target. Add at least one model.',
                )
                : DoctorResult::pass(sprintf(
                    '%d impersonatable %s: %s.',
                    count($types),
                    Str::plural('type', count($types)),
                    implode(', ', array_keys($types)),
                ));
        }, 'read the target allowlist');
    }
}
