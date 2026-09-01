<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Login;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;
use Simtabi\Laranail\Impersonator\Core\Exceptions\TokenRejected;
use Simtabi\Laranail\Impersonator\Laravel\Drivers\TenancyDriver;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\Tenant;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;
use Stancl\Tenancy\TenancyServiceProvider;

uses()->group('tenancy');

beforeEach(function (): void {
    // Bootstrappers off: this suite is about the impersonation handoff, not about stancl
    // switching databases. Leaving them on would make every assertion depend on multi-database
    // plumbing that has nothing to do with what is under test.
    config()->set('tenancy.bootstrappers', []);
    config()->set('tenancy.tenant_model', Tenant::class);
    config()->set('tenancy.central_domains', ['admin.example.com']);

    $this->app->register(TenancyServiceProvider::class);

    Schema::create('tenants', function (Blueprint $table): void {
        $table->string('id')->primary();
        $table->json('data')->nullable();
        $table->timestamps();
    });

    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('laranail.impersonator.driver', 'tenancy');
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 10);
    config()->set('laranail.impersonator.urls.strategy', 'subdomain');
    config()->set('laranail.impersonator.urls.base_domain', 'example.com');

    $this->tenant = Tenant::create(['id' => 'acme']);
    $this->other = Tenant::create(['id' => 'globex']);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

afterEach(function (): void {
    tenancy()->end();
});

/** Pull the raw token back out of an accept URL. */
function tenantToken(string $url): string
{
    return rawurldecode(basename(parse_url($url, PHP_URL_PATH) ?: ''));
}

it('is available when stancl is installed', function (): void {
    expect(Impersonator::driver('tenancy'))->toBeInstanceOf(TenancyDriver::class)
        ->and(Impersonator::driver('tenancy')->isAvailable())->toBeTrue()
        ->and(Impersonator::driver('tenancy')->requiresHandoff())->toBeTrue();
});

it('refuses to enter without an initialized tenant', function (): void {
    // A handoff URL has to address a specific tenant, and guessing produces a link to the wrong
    // host — so this fails with a clear message rather than issuing something broken.
    expect(fn () => Impersonator::enter($this->target))
        ->toThrow(ImpersonationException::class, 'initialized tenant');
});

it('mints a pending handoff addressed at the tenant', function (): void {
    tenancy()->initialize($this->tenant);

    $outcome = Impersonator::enter($this->target);

    expect($outcome->pending)->toBeTrue()
        ->and($outcome->acceptUrl())->toStartWith('https://acme.example.com/impersonator/accept/')
        ->and(Impersonator::isImpersonating())->toBeFalse();
});

it('records the tenant on the audit row', function (): void {
    tenancy()->initialize($this->tenant);

    $outcome = Impersonator::enter($this->target);

    expect(app(AuditStore::class)->find($outcome->auditId())->tenantId)->toBe('acme')
        ->and($outcome->session->driver)->toBe('tenancy');
});

it('completes the handoff on the same tenant', function (): void {
    tenancy()->initialize($this->tenant);
    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());

    $outcome = Impersonator::complete($token, 'tenancy');

    expect($outcome->isStarted())->toBeTrue()
        ->and(Auth::guard('web')->id())->toBe($this->target->getKey())
        ->and(Impersonator::isImpersonating())->toBeTrue();
});

it('regenerates the session on redemption, unlike stancl loginUsingId', function (): void {
    // The concrete reason this driver does not call UserImpersonation::makeResponse().
    tenancy()->initialize($this->tenant);
    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());

    $before = session()->getId();
    Impersonator::complete($token, 'tenancy');

    expect(session()->getId())->not->toBe($before);
});

it('does not fire the target login listeners on redemption', function (): void {
    Event::fake([Login::class]);
    tenancy()->initialize($this->tenant);
    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());

    Impersonator::complete($token, 'tenancy');

    Event::assertNotDispatched(Login::class);
});

// ── the tenant boundary ─────────────────────────────────────────────────────

it('refuses a token redeemed on a different tenant', function (): void {
    // The reason this driver exists separately from the token driver.
    tenancy()->initialize($this->tenant);
    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());

    tenancy()->end();
    tenancy()->initialize($this->other);

    expect(fn () => Impersonator::complete($token, 'tenancy'))->toThrow(TokenRejected::class);
    expect(Impersonator::isImpersonating())->toBeFalse();
});

it('gives a tenant mismatch the same message as an unknown token', function (): void {
    // Saying "wrong tenant" would confirm the token is real and disclose that another tenant
    // exists.
    tenancy()->initialize($this->tenant);
    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());

    tenancy()->end();
    tenancy()->initialize($this->other);

    $mismatch = null;
    $unknown = null;

    try {
        Impersonator::complete($token, 'tenancy');
    } catch (TokenRejected $e) {
        $mismatch = $e->getMessage();
    }

    try {
        Impersonator::complete(str_repeat('z', 60), 'tenancy');
    } catch (TokenRejected $e) {
        $unknown = $e->getMessage();
    }

    expect($mismatch)->toBe($unknown)
        ->and($mismatch)->not->toContain('tenant');
});

it('refuses a token that carries no tenant at all', function (): void {
    // A token minted outside a tenant did not come from this driver, so it is not redeemable
    // through it — even on a tenant that would otherwise be willing.
    config()->set('laranail.impersonator.driver', 'token');
    config()->set('laranail.impersonator.urls.strategy', 'domain');

    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());

    tenancy()->initialize($this->tenant);

    expect(fn () => Impersonator::complete($token, 'tenancy'))->toThrow(TokenRejected::class);
});

it('refuses a token redeemed with no tenant initialized', function (): void {
    tenancy()->initialize($this->tenant);
    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());

    tenancy()->end();

    expect(fn () => Impersonator::complete($token, 'tenancy'))->toThrow(TokenRejected::class);
});

// ── token properties carry over ─────────────────────────────────────────────

it('stores the token as a digest, not in plaintext', function (): void {
    // stancl's own feature stores the token id unhashed as a primary key; this does not.
    tenancy()->initialize($this->tenant);
    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());

    $rows = DB::table('impersonator_tokens')->get();

    expect($rows)->toHaveCount(1)
        ->and($rows[0]->token_hash)->toBe(hash('sha256', $token))
        ->and(json_encode($rows))->not->toContain($token);
});

it('refuses a replayed token', function (): void {
    tenancy()->initialize($this->tenant);
    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());

    Impersonator::complete($token, 'tenancy');
    Impersonator::leave();

    expect(fn () => Impersonator::complete($token, 'tenancy'))->toThrow(TokenRejected::class);
});

it('refuses an expired token', function (): void {
    config()->set('laranail.impersonator.tokens.ttl', 60);
    tenancy()->initialize($this->tenant);
    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());

    $this->travel(61)->seconds();

    expect(fn () => Impersonator::complete($token, 'tenancy'))->toThrow(TokenRejected::class);
});

it('re-runs authorization at redemption', function (): void {
    tenancy()->initialize($this->tenant);
    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());

    $this->target->delete();

    expect(fn () => Impersonator::complete($token, 'tenancy'))
        ->toThrow(ImpersonationDenied::class);
});

it('leaves cleanly', function (): void {
    tenancy()->initialize($this->tenant);
    $token = tenantToken(Impersonator::enter($this->target)->acceptUrl());
    $outcome = Impersonator::complete($token, 'tenancy');

    Impersonator::leave();

    expect(Impersonator::isImpersonating())->toBeFalse()
        ->and(app(AuditStore::class)->find($outcome->auditId())->hasEnded())->toBeTrue();
});

// ── auto driver resolution ──────────────────────────────────────────────────

it('resolves auto to tenancy when a tenant is initialized', function (): void {
    config()->set('laranail.impersonator.driver', 'auto');

    tenancy()->initialize($this->tenant);

    expect(Impersonator::defaultDriver())->toBe('tenancy');
});

it('resolves auto to session when no tenant is initialized', function (): void {
    config()->set('laranail.impersonator.driver', 'auto');

    expect(Impersonator::defaultDriver())->toBe('session');
});

it('never second-guesses an explicit driver even inside a tenant', function (): void {
    config()->set('laranail.impersonator.driver', 'session');

    tenancy()->initialize($this->tenant);

    expect(Impersonator::defaultDriver())->toBe('session');
});
