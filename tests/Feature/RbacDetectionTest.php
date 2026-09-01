<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\BasePolicy;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/*
| Which policy gets selected, and by what.
|
| The RBAC policy is duck-typed against `hasPermissionTo()` / `hasRole()`, so nothing about it is
| spatie-specific except which class name is probed to *detect* a permission layer. That probe used to
| be a hardcoded `class_exists(Spatie\…\PermissionServiceProvider::class)` — a compile-time reference
| to a package that is not even a dev dependency here.
|
| Detection only ever chooses a default. An explicit `authorization.policy` wins over all of it.
*/

/** A stand-in for a permission package's service provider. Its only job is to exist. */
final class FakePermissionProvider {}

/**
 * The exact class the container selects, resolved fresh.
 *
 * The **exact** class, deliberately: `RbacPolicy` extends `BasePolicy`, so an `instanceof BasePolicy`
 * assertion is satisfied by either one and would prove nothing about which was chosen.
 *
 * @return class-string<AuthorizationPolicy>
 */
function selectedPolicy(): string
{
    // Forget the singleton so each case resolves against the config it just set.
    app()->forgetInstance(AuthorizationPolicy::class);

    return app(AuthorizationPolicy::class)::class;
}

it('falls back to the base policy when no permission package is present', function (): void {
    config()->set('laranail.impersonator.authorization.rbac.detect', ['Some\\Package\\ThatIsNotInstalled']);

    expect(selectedPolicy())->toBe(BasePolicy::class);
});

it('selects the RBAC policy from a configured class list', function (): void {
    // The point of the change: a different permission package is now a config edit rather than a
    // pull request.
    config()->set('laranail.impersonator.authorization.rbac.detect', [FakePermissionProvider::class]);

    expect(selectedPolicy())->toBe(RbacPolicy::class);
});

it('probes every name in the list, not only the first', function (): void {
    config()->set('laranail.impersonator.authorization.rbac.detect', [
        'Some\\Package\\ThatIsNotInstalled',
        FakePermissionProvider::class,
    ]);

    expect(selectedPolicy())->toBe(RbacPolicy::class);
});

it('defaults to probing spatie when the list is empty or malformed', function (): void {
    // Empty must mean "use the default", not "detect nothing" — otherwise an application that
    // cleared the key would silently lose its permission enforcement.
    config()->set('laranail.impersonator.authorization.rbac.detect', []);

    expect(app(ImpersonationManager::class)->detectsRbac())
        ->toBe(class_exists('Spatie\\Permission\\PermissionServiceProvider'));
});

it('lets a runtime closure decide', function (): void {
    config()->set('laranail.impersonator.authorization.rbac.detect', ['Some\\Package\\ThatIsNotInstalled']);

    Impersonator::detectRbacUsing(fn (): bool => true);

    expect(selectedPolicy())->toBe(RbacPolicy::class);
});

it('lets a closure veto a class list that would otherwise match', function (): void {
    config()->set('laranail.impersonator.authorization.rbac.detect', [FakePermissionProvider::class]);

    Impersonator::detectRbacUsing(fn (): bool => false);

    expect(selectedPolicy())->toBe(BasePolicy::class);
});

it('fails closed when a closure returns something other than true', function (): void {
    // A truthy string is not a yes. Reading it as one would hand the RBAC policy a permission
    // system it cannot query, and a policy that cannot query its permissions cannot enforce them.
    foreach (['yes', 1, [], null, 0.0] as $value) {
        app()->forgetInstance(ImpersonationManager::class);
        Impersonator::clearResolvedInstances();
        Impersonator::detectRbacUsing(fn (): mixed => $value);

        expect(selectedPolicy())->toBe(BasePolicy::class);
    }
});

it('fails closed when a closure throws', function (): void {
    Impersonator::detectRbacUsing(function (): bool {
        throw new RuntimeException('the permission package exploded');
    });

    expect(selectedPolicy())->toBe(BasePolicy::class);
});

it('lets an explicit policy override detection entirely', function (): void {
    // Both layers say yes; the explicit setting still wins. This is the escape hatch for an
    // application that has a permission package but does not want it governing impersonation.
    config()->set('laranail.impersonator.authorization.rbac.detect', [FakePermissionProvider::class]);
    Impersonator::detectRbacUsing(fn (): bool => true);
    config()->set('laranail.impersonator.authorization.policy', BasePolicy::class);

    expect(selectedPolicy())->toBe(BasePolicy::class);
});

it('does not reference the spatie provider at compile time', function (): void {
    // The regression that matters. A hard `use Spatie\...` import in the provider is a compile-time
    // dependency on a package this one does not require, even as a dev dependency.
    $provider = file_get_contents(
        dirname(__DIR__, 2).'/src/Laravel/Providers/ImpersonatorServiceProvider.php',
    );

    expect($provider)->not->toContain('use Spatie\\')
        ->and($provider)->not->toContain('PermissionServiceProvider');
});
