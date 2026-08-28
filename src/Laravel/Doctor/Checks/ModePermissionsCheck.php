<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;

/**
 * The trap: an operator holding `impersonator.enter` and no mode permission.
 *
 * Both are required, so such an operator can impersonate nothing at all while appearing fully
 * configured. The error they get names the *mode*, which sends them asking for the wrong permission —
 * and this is the single most common way an install is quietly broken.
 *
 * Keyed on the **active policy** rather than on whether an RBAC package is installed. Those are not
 * the same question: the policy is what actually decides, it can be set explicitly in config, and an
 * install naming `RbacPolicy` without spatie present still enforces per-mode permissions. Checking
 * for the package would tell that install any mode is allowed.
 */
final class ModePermissionsCheck extends Check
{
    public function name(): string
    {
        return 'Mode permissions';
    }

    public function description(): string
    {
        return 'Whether entering needs a per-mode permission as well as the enter permission.';
    }

    public function run(): DoctorResult
    {
        $policy = $this->resolve(AuthorizationPolicy::class);

        if ($policy === null) {
            return DoctorResult::fail(
                'The authorization policy could not be built, so mode permissions were not checked.',
            );
        }

        if (! $policy instanceof RbacPolicy) {
            return DoctorResult::pass(sprintf(
                'The active policy is [%s], which does not check per-mode permissions, so any '
                . 'registered mode may be used.',
                $policy::class,
            ));
        }

        $template = $this->settings->string('authorization.permissions.mode', 'impersonator.mode.%s');
        $enter = $this->settings->string('authorization.permissions.enter', 'impersonator.enter');
        $default = $this->settings->string('default_mode', 'full');

        return DoctorResult::warn(sprintf(
            'Entering needs BOTH [%s] and the per-mode permission — for the default mode that is '
            . '[%s]. Granting only the first produces an operator who can impersonate nothing '
            . 'while looking correctly configured. Verify your seeder grants both.',
            $enter,
            sprintf($template, $default),
        ));
    }
}
