<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Simtabi\Laranail\Impersonator\Laravel\Concerns\Impersonates;

/** A user model with the trait applied and both hooks left at their defaults. */
class StaffUser extends Authenticatable
{
    use Impersonates;
    use SoftDeletes;

    protected $table = 'users';

    protected $guarded = [];
}
