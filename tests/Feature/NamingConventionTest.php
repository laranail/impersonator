<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\View;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\RateLimiter;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;
use Simtabi\Laranail\Package\Tools\Testing\NamingScope;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\RbacUser;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\DeprecatedNames;
use Simtabi\Laranail\Package\Tools\Testing\AssertsRegisteredNames;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Package\Tools\Support\Routing\BareRouteNameAliases;

/*
| Every name the package registers carries its vendor and slug, read from the live registries of a
| booted application rather than grepped from the provider. The bare names shipped before 0.1 are
| listed explicitly as deprecated aliases -- an allow-list entry is a ceiling, so a stale one fails --
| and the second half of the file proves each of them still works and announces itself.
*/

uses(AssertsRegisteredNames::class);

beforeEach(function (): void {
    config()->set('laranail.impersonator.api.enabled', true);
    config()->set('laranail.impersonator.api.middleware', ['api']);

    // The API routes load during boot, so re-run the route registration with the API on.
    require dirname(__DIR__, 2) . '/routes/api.php';
    app('router')->getRoutes()->refreshNameLookups();

    DeprecatedNames::forgetWarnings();
    BareRouteNameAliases::forgetWarnings();

    // The base path is passed explicitly. The default is the parent of `src/`, which in this
    // checkout also holds `vendor/` -- so every framework closure and view path would read as the
    // package's own. `src/` for code-registered names, `resources/` for the view and lang paths.
    $root = dirname(__DIR__, 2);

    $this->scope = NamingScope::for('laranail/impersonator', 'Simtabi\\Laranail\\Impersonator\\', $root . '/src');
    $this->resourceScope = NamingScope::for('laranail/impersonator', 'Simtabi\\Laranail\\Impersonator\\', $root . '/resources');
});

/**
 * Run $callback and return the E_USER_DEPRECATED messages it raised.
 *
 * @return list<string>
 */
function impersonatorDeprecations(Closure $callback): array
{
    $messages = [];

    set_error_handler(static function (int $level, string $message) use (&$messages): bool {
        $messages[] = $message;

        return true;
    }, E_USER_DEPRECATED);

    try {
        $callback();
    } finally {
        restore_error_handler();
    }

    return $messages;
}

// ── live registries ─────────────────────────────────────────────────────────

it('scopes every route name, web and api', function (): void {
    $names = $this->assertRouteNamesScoped($this->scope, atLeast: 18);

    expect($names)->toContain(
        'laranail-impersonator.enter',
        'laranail-impersonator.leave',
        'laranail-impersonator.extend',
        'laranail-impersonator.revoke',
        'laranail-impersonator.accept',
        'laranail-impersonator.api.impersonations.store',
        'laranail-impersonator.api.approvals.deny',
    );
});

it('scopes every rate limiter, keeping the bare ones only as deprecated aliases', function (): void {
    $names = $this->assertRateLimitersScoped(
        $this->scope,
        deprecated: array_keys(DeprecatedNames::RATE_LIMITERS),
        atLeast: 3,
    );

    expect($names)->toContain(...array_values(DeprecatedNames::RATE_LIMITERS));
});

it('scopes every gate ability, keeping the bare ones only as deprecated aliases', function (): void {
    $names = $this->assertGateAbilitiesScoped(
        $this->scope,
        deprecated: array_keys(DeprecatedNames::GATE_ABILITIES),
        atLeast: 3,
    );

    expect($names)->toContain(...array_values(DeprecatedNames::GATE_ABILITIES));
});

it('scopes every Blade component, keeping the bare tags only as deprecated aliases', function (): void {
    $names = $this->assertBladeComponentsScoped(
        $this->scope,
        deprecated: array_keys(DeprecatedNames::BLADE_COMPONENTS),
        atLeast: 5,
    );

    expect($names)->toContain(...array_values(DeprecatedNames::BLADE_COMPONENTS));
});

it('scopes the container alias, keeping the bare one only as a deprecated alias', function (): void {
    $names = $this->assertContainerAliasesScoped(
        $this->scope,
        deprecated: array_keys(DeprecatedNames::CONTAINER_ALIASES),
    );

    expect($names)->toContain(DeprecatedNames::CONTAINER_ALIAS)
        ->and(app(DeprecatedNames::CONTAINER_ALIAS))->toBe(app(ImpersonationManager::class));
});

it('scopes every middleware alias', function (): void {
    expect($this->assertMiddlewareAliasesScoped($this->scope, atLeast: 5))
        ->toContain('laranail-impersonator.lifetime', 'laranail-impersonator.rls');
});

it('registers views and translations under both scoped forms', function (): void {
    expect($this->assertViewNamespacesScoped($this->resourceScope, atLeast: 2))
        ->toContain('laranail/impersonator', 'laranail-impersonator')
        ->and($this->assertTranslationNamespacesScoped($this->resourceScope, atLeast: 2))
        ->toContain('laranail/impersonator', 'laranail-impersonator')
        ->and(View::exists('laranail/impersonator::banner'))->toBeTrue()
        ->and(Lang::has('laranail/impersonator::banner.leave'))->toBe(Lang::has('laranail-impersonator::banner.leave'));
});

it('scopes every artisan command', function (): void {
    expect($this->assertCommandNamesScoped($this->scope, atLeast: 1))
        ->each->toStartWith('laranail::impersonator.');
});

// ── the deprecated names still work ─────────────────────────────────────────

it('resolves every bare route name to its scoped route, and announces it once', function (): void {
    $map = [];

    foreach (app('router')->getRoutes()->getRoutes() as $route) {
        $name = (string) $route->getName();

        if (str_starts_with($name, DeprecatedNames::ROUTE_PREFIX)) {
            $map[(string) DeprecatedNames::legacyRouteName($name)] = $name;
        }
    }

    expect($map)->toHaveCount(18);

    $parameters = [];

    foreach (array_keys($map) as $bare) {
        $parameters[$bare] = ['audit' => 'a1', 'token' => 't1', 'approval' => 'p1'];
    }

    $this->assertDeprecatedRouteNamesResolve($map, $parameters);

    BareRouteNameAliases::forgetWarnings();

    $messages = impersonatorDeprecations(static function (): void {
        route('impersonator.leave');
        route('impersonator.leave');
    });

    expect($messages)->toHaveCount(1)
        ->and($messages[0])->toContain('impersonator.leave')
        ->and($messages[0])->toContain('laranail-impersonator.leave');
});

it('keeps a bare rate limiter delegating to the scoped one, and announces it once', function (): void {
    config()->set('laranail.impersonator.rate_limiting.accept.attempts', 7);

    $request = Request::create('/');

    $messages = impersonatorDeprecations(static function () use ($request, &$limit): void {
        $limit = RateLimiter::limiter('impersonator-accept')($request);
        RateLimiter::limiter('impersonator-accept')($request);
    });

    $scoped = RateLimiter::limiter('laranail-impersonator.accept')($request);

    expect($limit)->toBeInstanceOf(Limit::class)
        ->and($limit->maxAttempts)->toBe(7)
        ->and($limit->key)->toBe($scoped->key)
        ->and($messages)->toBe([
            DeprecatedNames::message('rate limiter', 'impersonator-accept', 'laranail-impersonator.accept'),
        ]);
});

it('throttles a host route that still names a bare limiter', function (): void {
    config()->set('laranail.impersonator.rate_limiting.accept.attempts', 1);

    Route::get('/host-throttled', static fn (): string => 'ok')->middleware('throttle:impersonator-accept');

    $this->get('/host-throttled')->assertOk();
    $this->get('/host-throttled')->assertStatus(429);
});

it('keeps each bare gate ability delegating to its scoped ability, and announces it once', function (): void {
    Schema::create('users', static function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->json('permissions')->nullable();
        $table->json('roles')->nullable();
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.authorization.policy', RbacPolicy::class);
    config()->set('auth.providers.users.model', RbacUser::class);
    app()->forgetInstance(AuthorizationPolicy::class);

    $viewer = RbacUser::create(['name' => 'Viewer', 'permissions' => ['laranail-impersonator.audit.view']]);
    $nobody = RbacUser::create(['name' => 'Nobody', 'permissions' => []]);

    $messages = impersonatorDeprecations(static function () use ($viewer, $nobody, &$answers): void {
        $answers = [
            Gate::forUser($viewer)->allows('impersonator.audit.view'),
            Gate::forUser($viewer)->allows('laranail-impersonator.audit.view'),
            Gate::forUser($nobody)->allows('impersonator.audit.view'),
            Gate::forUser($nobody)->allows('laranail-impersonator.audit.view'),
        ];
    });

    expect($answers)->toBe([true, true, false, false])
        ->and($messages)->toBe([
            DeprecatedNames::message('gate ability', 'impersonator.audit.view', 'laranail-impersonator.audit.view'),
        ]);
});

it('lets an application keep its own definition of a bare ability', function (): void {
    // Application providers boot after package ones in a real install; re-running the package's
    // gate registration over an app-defined ability is the same ordering question.
    Gate::define('impersonator.revoke', static fn (): bool => true);

    new Simtabi\Laranail\Impersonator\Laravel\Providers\ImpersonatorServiceProvider(app())->boot();

    expect(Gate::forUser(new User)->allows('impersonator.revoke', ['x']))->toBeTrue();
});

it('accepts an operator seeded with the bare permission names, and announces it', function (): void {
    Schema::create('users', static function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->json('permissions')->nullable();
        $table->json('roles')->nullable();
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.authorization.policy', RbacPolicy::class);
    config()->set('auth.providers.users.model', RbacUser::class);
    app()->forgetInstance(AuthorizationPolicy::class);

    $legacy = RbacUser::create(['name' => 'Legacy', 'permissions' => ['impersonator.enter', 'impersonator.mode.full']]);
    $scoped = RbacUser::create(['name' => 'Scoped', 'permissions' => ['laranail-impersonator.enter', 'laranail-impersonator.mode.full']]);
    $nobody = RbacUser::create(['name' => 'Nobody', 'permissions' => []]);

    $policy = app(AuthorizationPolicy::class);
    $identity = static fn (RbacUser $user) => app(IdentityResolver::class)->fromUser($user);

    $messages = impersonatorDeprecations(static function () use ($policy, $identity, $legacy, $scoped, $nobody, &$answers): void {
        $answers = [
            $policy->authorizeMode($identity($legacy), 'full')->allowed,
            $policy->authorizeMode($identity($scoped), 'full')->allowed,
            $policy->authorizeMode($identity($nobody), 'full')->allowed,
        ];
    });

    expect($answers)->toBe([true, true, false])
        ->and($messages)->toContain(
            DeprecatedNames::message('permission', 'impersonator.enter', 'laranail-impersonator.enter'),
            DeprecatedNames::message('permission', 'impersonator.mode.full', 'laranail-impersonator.mode.full'),
        );
});

it('gives a configured permission name no bare fallback', function (): void {
    Schema::create('users', static function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->json('permissions')->nullable();
        $table->json('roles')->nullable();
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.authorization.policy', RbacPolicy::class);
    config()->set('laranail.impersonator.authorization.permissions.revoke', 'acme.revoke');
    config()->set('auth.providers.users.model', RbacUser::class);
    app()->forgetInstance(AuthorizationPolicy::class);

    $legacy = RbacUser::create(['name' => 'Legacy', 'permissions' => ['impersonator.revoke']]);

    expect(app(AuthorizationPolicy::class)->authorizeRevoke(app(IdentityResolver::class)->fromUser($legacy), 'a1')->allowed)
        ->toBeFalse();
});

it('announces a bare Blade tag once, when its template is compiled', function (): void {
    $messages = impersonatorDeprecations(static function (): void {
        Blade::compileString('<x-impersonation-badge /><x-impersonation-badge/><x-laranail-impersonator::badge />');
        Blade::compileString('<x-impersonation-badge />');
    });

    expect($messages)->toBe([
        DeprecatedNames::message('Blade component', '<x-impersonation-badge>', '<x-laranail-impersonator::badge>'),
    ]);
});

it('does not announce the scoped or class-derived tags', function (): void {
    $messages = impersonatorDeprecations(static function (): void {
        Blade::compileString('<x-laranail-impersonator::banner /><x-laranail-impersonator::impersonation-banner />');
    });

    expect($messages)->toBe([]);
});

it('keeps the bare container alias resolving to the manager', function (): void {
    expect(app('impersonator'))->toBe(app(DeprecatedNames::CONTAINER_ALIAS))
        ->and(app('impersonator'))->toBeInstanceOf(ImpersonationManager::class);
});

it('keeps a pre-0.1 read-only allowlist naming a bare route as an exit', function (): void {
    $enforcer = app(Simtabi\Laranail\Impersonator\Laravel\Modes\ReadOnlyModeEnforcer::class);

    config()->set('laranail.impersonator.modes.read_only.allowed_routes', ['impersonator.extend']);

    $action = Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction::http('POST', '/impersonator/extend', 'laranail-impersonator.extend');

    expect(DeprecatedNames::legacyRouteName('laranail-impersonator.extend'))->toBe('impersonator.extend')
        ->and(DeprecatedNames::legacyRouteName('dashboard'))->toBeNull()
        ->and(new ReflectionMethod($enforcer, 'isAllowedRoute')->invoke($enforcer, $action))->toBeTrue();
});

it('keeps a pre-0.1 limited-mode deny-list naming a bare route denying the scoped one', function (): void {
    // The direction that matters: a deny-list that silently stopped matching would widen what an
    // impersonated session may do.
    $enforcer = app(Simtabi\Laranail\Impersonator\Laravel\Modes\LimitedModeEnforcer::class);

    config()->set('laranail.impersonator.modes.limited.deny_routes', ['impersonator.revoke']);

    $scoped = Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction::http('POST', '/impersonator/revoke/a1', 'laranail-impersonator.revoke');
    $other = Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction::http('POST', '/impersonator/extend', 'laranail-impersonator.extend');
    $denied = new ReflectionMethod($enforcer, 'deniedByRoute');

    expect($denied->invoke($enforcer, $scoped))->toBeTrue()
        ->and($denied->invoke($enforcer, $other))->toBeFalse();
});
