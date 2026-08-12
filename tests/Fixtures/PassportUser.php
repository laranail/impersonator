<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;

/**
 * A Passport user.
 *
 * The interface is not optional: Passport's `HasApiTokens` carries
 * `@phpstan-require-implements OAuthenticatable`, so the trait and the contract go together —
 * which is why the adapter checks for the contract rather than probing for a method.
 */
class PassportUser extends Authenticatable implements OAuthenticatable
{
    use HasApiTokens;
    use SoftDeletes;

    protected $table = 'users';

    protected $guarded = [];
}
