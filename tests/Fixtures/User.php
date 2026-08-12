<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

/**
 * @property string $name
 */
class User extends Authenticatable
{
    // Notifiable is not on Illuminate's base user — an application's own User model adds
    // it. Included here so the fixture matches what consumers actually have.
    use Notifiable;
    use SoftDeletes;

    protected $table = 'users';

    protected $guarded = [];
}
