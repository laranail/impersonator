<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

/**
 * A weak check on purpose.
 *
 * The scheduler is defined in the application's own bootstrap and there is no reliable way to ask
 * "is this command scheduled". Reporting a warning a host may safely ignore beats silently assuming
 * the sweep runs — an unanswered request that nobody sweeps never tells its requester that nobody
 * replied.
 */
final class ApprovalPruneCheck extends Check
{
    public function name(): string
    {
        return 'Approval pruning';
    }

    public function description(): string
    {
        return 'Whether the sweep that expires unanswered requests is scheduled.';
    }

    public function run(): DoctorResult
    {
        if (! $this->settings->bool('approval.require', false)) {
            return DoctorResult::skip('Approval is not required, so there is nothing to prune.');
        }

        return DoctorResult::warn(
            'Schedule laranail::impersonator.prune-approvals, or an operator whose request went '
            .'unanswered is never told that nobody replied.',
        );
    }
}
