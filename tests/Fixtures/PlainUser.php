<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;

/** A user model without Notifiable, to exercise the non-notifiable warning path. */
class PlainUser extends Authenticatable
{
    use SoftDeletes;

    protected $table = 'users';

    protected $guarded = [];
}
