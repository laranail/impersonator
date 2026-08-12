<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Tests\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use RuntimeException;

/**
 * A user exposing the RBAC surface the policy duck-types against — `hasPermissionTo`
 * and `hasRole`, the shape spatie/laravel-permission uses.
 *
 * Permissions and roles are stored as JSON columns so a test can set them without a
 * pivot table. `hasPermissionTo` throws for an unregistered permission, exactly as
 * spatie's does, so the policy's handling of that case is covered rather than assumed.
 */
class RbacUser extends Authenticatable
{
    // Notifiable is not on Illuminate's base user — an application's own User model adds it.
    // Needed here because break-glass approvals notify the operator and the approvers, and
    // PlainUser is the fixture that covers the non-notifiable path.
    use Notifiable;
    use SoftDeletes;

    /** Permissions the application is deemed to know about. Anything else throws. */
    public static array $registered = [];

    protected $table = 'users';

    protected $guarded = [];

    protected $casts = [
        'permissions' => 'array',
        'roles' => 'array',
    ];

    public function hasPermissionTo(string $permission): bool
    {
        if (static::$registered !== [] && ! in_array($permission, static::$registered, true)) {
            throw new RuntimeException(sprintf('There is no permission named [%s].', $permission));
        }

        return in_array($permission, $this->permissionList(), true);
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roleList(), true);
    }

    /** @return list<string> */
    private function permissionList(): array
    {
        $value = $this->getAttribute('permissions');

        return is_array($value) ? array_values(array_filter($value, is_string(...))) : [];
    }

    /** @return list<string> */
    private function roleList(): array
    {
        $value = $this->getAttribute('roles');

        return is_array($value) ? array_values(array_filter($value, is_string(...))) : [];
    }
}
