<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests\Fixtures;

use Stancl\Tenancy\Database\Models\Tenant as BaseTenant;

/** A minimal stancl tenant, keyed by a string id. */
class Tenant extends BaseTenant
{
    protected $table = 'tenants';
}
