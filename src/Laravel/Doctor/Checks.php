<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor;

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\GateCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\DriverCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\GuardsCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\OctaneCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\TablesCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\AdapterCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\RestApiCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\TargetsCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\ApprovalCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\ExtensionCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\BootHealthCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\HandoffUrlCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\MaxDurationCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\MasterSwitchCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\ApprovalPruneCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\TamperEvidenceCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\ModePermissionsCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\RowLevelSecurityCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\SessionTerminationCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\ConflictingPackagesCheck;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\ApprovalNotificationsCheck;

/**
 * The diagnostic set, in report order.
 *
 * One list, consumed by two callers: this package's own `laranail::impersonator.doctor`, and the
 * family-wide `laranail::package-tools.doctor` that the service provider registers these into. A
 * second list would be how the two came to disagree.
 *
 * Order is deliberate rather than alphabetical — cheap, unconditional facts first (is it even on,
 * did boot survive, is the trail trustworthy, do the tables exist), then the things that need the
 * container, then the posture questions. An install broken in an early check usually explains the
 * later ones.
 */
final class Checks
{
    /** @return list<class-string<Check>> */
    public static function all(): array
    {
        return [
            MasterSwitchCheck::class,
            BootHealthCheck::class,
            TamperEvidenceCheck::class,
            TablesCheck::class,

            TargetsCheck::class,
            GuardsCheck::class,
            DriverCheck::class,
            AdapterCheck::class,
            HandoffUrlCheck::class,

            ModePermissionsCheck::class,
            GateCheck::class,
            SessionTerminationCheck::class,

            MaxDurationCheck::class,
            ExtensionCheck::class,

            ApprovalCheck::class,
            ApprovalNotificationsCheck::class,
            ApprovalPruneCheck::class,

            RestApiCheck::class,
            OctaneCheck::class,
            RowLevelSecurityCheck::class,
            ConflictingPackagesCheck::class,
        ];
    }
}
