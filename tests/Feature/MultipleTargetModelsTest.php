<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\Vendor;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Laravel\Support\TargetRegistry;
use Simtabi\Laranail\Impersonator\Laravel\Support\BannerPresenter;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;

/*
| More than one impersonatable model — the normal case for anything beyond a single-model
| application. A customer on the `web` guard and a vendor on its own `vendor` guard, both
| impersonatable, both landing in one morph-keyed audit table.
*/

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    Schema::create('vendors', function (Blueprint $table): void {
        $table->id();
        $table->string('company_name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('auth.providers.users.model', User::class);
    config()->set('auth.providers.vendors', ['driver' => 'eloquent', 'model' => Vendor::class]);
    config()->set('auth.guards.vendor', ['driver' => 'session', 'provider' => 'vendors']);

    config()->set('laranail.impersonator.targets.allowlist', [
        'user'   => User::class,
        'vendor' => [
            'model'        => Vendor::class,
            'guard'        => 'vendor',
            'display_name' => 'company_name',
            'label'        => 'Vendor account',
        ],
    ]);
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 5);

    app(TargetRegistry::class)->flush();

    $this->admin = User::create(['name' => 'Admin']);
    $this->customer = User::create(['name' => 'Customer']);
    $this->vendor = Vendor::create(['company_name' => 'Acme Supplies Ltd']);

    $this->startSession();
});

// ── registry ────────────────────────────────────────────────────────────────

it('registers both the simple and the descriptive config forms', function (): void {
    // Supporting both shapes means adding a second model never forces rewriting the first.
    $registry = app(TargetRegistry::class);

    expect($registry->aliases())->toBe(['user', 'vendor'])
        ->and($registry->find('user')?->model)->toBe(User::class)
        ->and($registry->find('user')?->guard)->toBeNull()
        ->and($registry->find('vendor')?->model)->toBe(Vendor::class)
        ->and($registry->find('vendor')?->guard)->toBe('vendor')
        ->and($registry->find('vendor')?->displayName)->toBe('company_name');
});

it('finds a type by alias, class or model instance', function (): void {
    // Callers legitimately hold different forms: request input carries the alias, a Blade
    // component holds a model, an old audit row may carry a class name.
    $registry = app(TargetRegistry::class);

    expect($registry->find('vendor')?->alias)->toBe('vendor')
        ->and($registry->find(Vendor::class)?->alias)->toBe('vendor')
        ->and($registry->forModel($this->vendor)?->alias)->toBe('vendor')
        ->and($registry->find('nope'))->toBeNull();
});

it('exposes human labels for a type picker', function (): void {
    expect(app(TargetRegistry::class)->labels())->toBe([
        'user'   => 'User',
        'vendor' => 'Vendor account',
    ]);
});

it('drops an entry that is not an installed Eloquent model', function (): void {
    config()->set('laranail.impersonator.targets.allowlist', [
        'user'   => User::class,
        'ghost'  => 'App\\Models\\Removed',
        'broken' => ['guard' => 'vendor'],
    ]);
    app(TargetRegistry::class)->flush();

    expect(app(TargetRegistry::class)->aliases())->toBe(['user']);
});

// ── per-model guard ─────────────────────────────────────────────────────────

it('authenticates each target on its own guard', function (): void {
    // The gap a single global target guard cannot fill: authenticating a vendor against
    // the customer provider would find a different account with the same id.
    Auth::guard('web')->setUser($this->admin);

    $outcome = Impersonator::enter($this->vendor);

    expect($outcome->session->guards->target)->toBe('vendor')
        ->and(Auth::guard('vendor')->id())->toBe($this->vendor->getKey())
        ->and(Auth::guard('web')->id())->toBe($this->admin->getKey());
});

it('falls back to the global guard for a type that declares none', function (): void {
    Auth::guard('web')->setUser($this->admin);

    $outcome = Impersonator::enter($this->customer);

    expect($outcome->session->guards->target)->toBe('web')
        ->and(Auth::guard('web')->id())->toBe($this->customer->getKey());
});

it('resolves the guard pair for a type without impersonating', function (): void {
    expect(Impersonator::guardsFor('vendor')->target)->toBe('vendor')
        ->and(Impersonator::guardsFor('user')->target)->toBe('web')
        ->and(Impersonator::guardsFor('unknown')->target)->toBe('web');
});

it('leaves a vendor impersonation on the right guard', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->vendor);

    Impersonator::leave();

    expect(Auth::guard('vendor')->check())->toBeFalse()
        ->and(Auth::guard('web')->id())->toBe($this->admin->getKey())
        ->and(Impersonator::isImpersonating())->toBeFalse();
});

// ── audit rows ──────────────────────────────────────────────────────────────

it('records the morph alias so both models share one audit table', function (): void {
    Auth::guard('web')->setUser($this->admin);

    $vendorAudit = Impersonator::enter($this->vendor)->auditId();
    Impersonator::leave();
    $customerAudit = Impersonator::enter($this->customer)->auditId();

    $store = app(AuditStore::class);

    expect($store->find($vendorAudit)->target->type)->toBe('vendor')
        ->and($store->find($vendorAudit)->guards->target)->toBe('vendor')
        ->and($store->find($customerAudit)->target->type)->toBe('user')
        ->and($store->find($customerAudit)->guards->target)->toBe('web');
});

it('labels each model by its own display attribute', function (): void {
    // `name` is not universal — a vendor is `company_name`, and a single global setting
    // cannot describe both.
    Auth::guard('web')->setUser($this->admin);

    expect(Impersonator::enter($this->vendor)->session->target->label)->toBe('Acme Supplies Ltd');

    Impersonator::leave();

    expect(Impersonator::enter($this->customer)->session->target->label)->toBe('Customer');
});

it('shows the vendor label in the banner', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->vendor);

    expect(app(BannerPresenter::class)->render())
        ->toContain('Acme Supplies Ltd');
});

// ── runtime registration ────────────────────────────────────────────────────

it('accepts a type registered at runtime by another package', function (): void {
    // So a vendor module can register its own type from its own provider, without asking
    // the host application to edit config it does not own.
    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
    app(TargetRegistry::class)->flush();

    expect(app(TargetRegistry::class)->has('vendor'))->toBeFalse();

    Impersonator::registerTarget('vendor', Vendor::class, guard: 'vendor', displayName: 'company_name');

    expect(app(TargetRegistry::class)->has('vendor'))->toBeTrue();

    Auth::guard('web')->setUser($this->admin);

    expect(Impersonator::enter($this->vendor)->session->guards->target)->toBe('vendor');
});

it('lets a runtime registration override config of the same alias', function (): void {
    // The host application can always take back control, and this is the direction people
    // expect that override to work in.
    Impersonator::registerTarget('vendor', Vendor::class, guard: 'web', label: 'Overridden');

    expect(app(TargetRegistry::class)->find('vendor')?->guard)->toBe('web')
        ->and(app(TargetRegistry::class)->labels()['vendor'])->toBe('Overridden');
});

it('ignores a runtime registration for a class that is not a model', function (): void {
    Impersonator::registerTarget('nonsense', 'App\\Nope');

    expect(app(TargetRegistry::class)->has('nonsense'))->toBeFalse();
});

// ── the security boundary still holds ───────────────────────────────────────

it('still refuses a model that is registered nowhere', function (): void {
    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
    app(TargetRegistry::class)->flush();
    Auth::guard('web')->setUser($this->admin);

    expect(Impersonator::canImpersonate($this->vendor)->code)
        ->toBe(Decision::TARGET_NOT_ALLOWLISTED);
});

it('denies every target when nothing is registered', function (): void {
    config()->set('laranail.impersonator.targets.allowlist', []);
    app(TargetRegistry::class)->flush();
    Auth::guard('web')->setUser($this->admin);

    expect(app(TargetRegistry::class)->aliases())->toBe([])
        ->and(Impersonator::canImpersonate($this->customer)->denied())->toBeTrue();
});

it('applies the mode and the audit trail identically to a second model', function (): void {
    // Nothing about the modes, the trail or revocation is model-specific.
    Auth::guard('web')->setUser($this->admin);

    $auditId = Impersonator::enter($this->vendor, mode: 'read_only')->auditId();

    expect(Impersonator::mode()?->name)->toBe('read_only');

    Impersonator::revoke($auditId);

    expect(app(AuditStore::class)->find($auditId)->isRevoked())->toBeTrue();
});
