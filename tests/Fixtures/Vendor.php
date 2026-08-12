<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

/**
 * A second impersonatable model, on its own guard and labelled by a different attribute —
 * the multi-model case the target registry exists for.
 */
class Vendor extends Authenticatable
{
    use Notifiable;
    use SoftDeletes;

    protected $table = 'vendors';

    protected $guarded = [];
}
