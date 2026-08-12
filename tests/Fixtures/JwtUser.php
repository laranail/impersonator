<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;

/** A user model implementing tymon/jwt-auth's subject contract. */
class JwtUser extends Authenticatable implements JWTSubject
{
    use SoftDeletes;

    protected $table = 'users';

    protected $guarded = [];

    public function getJWTIdentifier(): mixed
    {
        return $this->getKey();
    }

    /** @return array<string, mixed> */
    public function getJWTCustomClaims(): array
    {
        return [];
    }
}
