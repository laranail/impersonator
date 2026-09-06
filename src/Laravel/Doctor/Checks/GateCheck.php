<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Illuminate\Contracts\Auth\Access\Gate;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

final class GateCheck extends Check
{
    public function name(): string
    {
        return 'Gate';
    }

    public function description(): string
    {
        return 'Whether the configured gate ability is actually defined.';
    }

    public function run(): DoctorResult
    {
        $ability = $this->settings->nullableString('authorization.gate_ability');

        if ($ability === null) {
            return DoctorResult::pass('No gate ability configured.');
        }

        $gate = $this->resolve(Gate::class);

        if ($gate === null) {
            return DoctorResult::fail('The gate could not be resolved, so the ability was not checked.');
        }

        return $gate->has($ability)
            ? DoctorResult::pass(sprintf('The [%s] ability is defined and will be consulted.', $ability))
            : DoctorResult::warn(sprintf(
                'impersonator.authorization.gate_ability is [%s] but no such ability is defined, '
                . 'so it is skipped. That is deliberate — an undefined ability denies everything '
                . 'in Laravel, and treating "not defined" as "denied" would break every install '
                . 'that never opted in — but if you meant to define it, it is not being enforced.',
                $ability,
            ));
    }
}
