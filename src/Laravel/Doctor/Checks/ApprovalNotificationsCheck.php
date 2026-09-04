<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

final class ApprovalNotificationsCheck extends Check
{
    public function name(): string
    {
        return 'Approval notifications';
    }

    public function description(): string
    {
        return 'Whether approvers are told a request is waiting.';
    }

    public function run(): DoctorResult
    {
        if (! $this->settings->bool('approval.require', false)) {
            return DoctorResult::skip('Approval is not required, so nobody needs notifying.');
        }

        return $this->settings->bool('notifications.approvals.enabled', false)
            ? DoctorResult::pass('Approvers are notified when a request is raised.')
            : DoctorResult::warn(
                'Approval is required but approver notifications are off '
                . '(impersonator.notifications.approvals.enabled). A queue nobody is told about gets '
                . 'checked after the incident, by which point the operator has asked a colleague to '
                . 'work around the control.',
            );
    }
}
