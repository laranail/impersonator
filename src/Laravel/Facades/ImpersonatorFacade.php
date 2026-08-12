<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Facades;

use Illuminate\Support\Facades\Facade;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/**
 * @method static \Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome enter(\Illuminate\Contracts\Auth\Authenticatable|\Illuminate\Database\Eloquent\Model $target, \Simtabi\Laranail\Impersonator\Core\Values\Mode|string|null $mode = null, ?string $reason = null, ?string $redirectTo = null, \Illuminate\Contracts\Auth\Authenticatable|\Illuminate\Database\Eloquent\Model|null $impersonator = null, ?string $driver = null, ?string $adapter = null, array $metadata = [])
 * @method static \Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome complete(string $token, ?string $driver = null)
 * @method static \Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession|null leave(\Simtabi\Laranail\Impersonator\Core\Enums\EndReason $reason = \Simtabi\Laranail\Impersonator\Core\Enums\EndReason::Left, ?string $driver = null)
 * @method static \Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession|null current()
 * @method static bool isImpersonating()
 * @method static \Illuminate\Contracts\Auth\Authenticatable|\Illuminate\Database\Eloquent\Model|null actor()
 * @method static \Illuminate\Contracts\Auth\Authenticatable|\Illuminate\Database\Eloquent\Model|null target()
 * @method static \Simtabi\Laranail\Impersonator\Core\Values\Mode|null mode()
 * @method static \Simtabi\Laranail\Impersonator\Core\Contracts\ImpersonationDriver driver(?string $name = null)
 * @method static \Simtabi\Laranail\Impersonator\Core\Contracts\AuthAdapter adapter(?string $name = null)
 * @method static \Simtabi\Laranail\Impersonator\Core\Support\ModeRegistry modes()
 * @method static \Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager extend(string $name, \Closure $factory)
 * @method static \Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager extendAdapter(string $name, \Closure $factory)
 * @method static \Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager registerMode(\Simtabi\Laranail\Impersonator\Core\Contracts\ModeEnforcer $enforcer)
 * @method static \Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager resolveAcceptUrlUsing(\Closure $resolver)
 * @method static \Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager displayNameUsing(\Closure $resolver)
 * @method static string|null displayNameFor(\Illuminate\Contracts\Auth\Authenticatable|\Illuminate\Database\Eloquent\Model|null $user)
 * @method static \Simtabi\Laranail\Impersonator\Core\Values\Decision canUseMode(\Simtabi\Laranail\Impersonator\Core\Values\Mode|string $mode, \Illuminate\Contracts\Auth\Authenticatable|\Illuminate\Database\Eloquent\Model|null $impersonator = null)
 * @method static \Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest buildRequest(\Illuminate\Contracts\Auth\Authenticatable|\Illuminate\Database\Eloquent\Model $target, \Simtabi\Laranail\Impersonator\Core\Values\Mode|string|null $mode = null, ?string $reason = null, ?string $redirectTo = null, \Illuminate\Contracts\Auth\Authenticatable|\Illuminate\Database\Eloquent\Model|null $impersonator = null, ?string $driver = null, ?string $adapter = null, array $metadata = [])
 * @method static \Simtabi\Laranail\Impersonator\Core\Values\Mode resolveMode(\Simtabi\Laranail\Impersonator\Core\Values\Mode|string|null $mode)
 * @method static \Simtabi\Laranail\Impersonator\Core\Values\Guards guards()
 * @method static \Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver identities()
 * @method static \Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy policy()
 * @method static string defaultDriver()
 * @method static string defaultAdapter()
 * @method static list<string> driverNames()
 * @method static list<string> adapterNames()
 * @method static bool hasDriver(string $name)
 * @method static bool hasAdapter(string $name)
 * @method static array<string, bool> driverAvailability()
 * @method static array<string, bool> adapterAvailability()
 *
 * @see ImpersonationManager
 */
class ImpersonatorFacade extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return ImpersonationManager::class;
    }
}
