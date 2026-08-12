<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;

/** An Eloquent model deliberately left out of the target allowlist. */
class Secret extends Model
{
    protected $table = 'secrets';

    protected $guarded = [];
}
