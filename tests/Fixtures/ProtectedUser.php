<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Simtabi\Laranail\Impersonator\Laravel\Concerns\Impersonates;

/**
 * Exercises both model hooks: this account refuses to be impersonated, and cannot
 * impersonate others either.
 */
class ProtectedUser extends Authenticatable
{
    use Impersonates;
    use SoftDeletes;

    protected $table = 'users';

    protected $guarded = [];

    public function canBeImpersonated(): bool
    {
        return false;
    }

    public function canImpersonate(): bool
    {
        return false;
    }
}
