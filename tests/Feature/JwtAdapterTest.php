<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Enums\CredentialType;
use Simtabi\Laranail\Impersonator\Laravel\Adapters\JwtAdapter;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\JwtUser;
use Tymon\JWTAuth\Providers\Auth\Illuminate;
use Tymon\JWTAuth\Providers\JWT\Lcobucci;
use Tymon\JWTAuth\Providers\LaravelServiceProvider;

uses()->group('jwt');

beforeEach(function (): void {
    // A fixed key so tokens are decodable in the assertions.
    config()->set('jwt.secret', str_repeat('a', 64));
    config()->set('jwt.ttl', 60);
    config()->set('jwt.blacklist_enabled', true);
    config()->set('jwt.providers', [
        'jwt' => Lcobucci::class,
        'auth' => Illuminate::class,
        'storage' => Tymon\JWTAuth\Providers\Storage\Illuminate::class,
    ]);

    $this->app->register(LaravelServiceProvider::class);

    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => JwtUser::class]);
    config()->set('auth.providers.users.model', JwtUser::class);
    config()->set('laranail.impersonator.adapter', 'jwt');
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 10);

    $this->admin = JwtUser::create(['name' => 'Admin']);
    $this->target = JwtUser::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

/** @return array<string, mixed> */
function decodeClaims(string $token): array
{
    [, $payload] = explode('.', $token);

    $decoded = json_decode(base64_decode(strtr($payload, '-_', '+/'), true) ?: '', true);

    return is_array($decoded) ? $decoded : [];
}

it('reports itself available when jwt-auth is installed', function (): void {
    expect(Impersonator::adapter('jwt')->isAvailable())->toBeTrue();
});

it('mints a JWT for the target', function (): void {
    $outcome = Impersonator::enter($this->target);

    expect($outcome->credential?->type)->toBe(CredentialType::Jwt)
        ->and($outcome->credential?->hasSecret())->toBeTrue()
        ->and(decodeClaims((string) $outcome->credential?->secret())['sub'])
        ->toBe((string) $this->target->getKey());
});

it('writes the impersonation claims into the token', function (): void {
    // A JWT may be presented to a service that has never heard of this package, so the facts
    // travel in the token rather than only in our database.
    $outcome = Impersonator::enter($this->target, mode: 'read_only');

    $claims = decodeClaims((string) $outcome->credential?->secret());

    expect($claims['imp_by'])->toBe('user:'.$this->admin->getKey())
        ->and($claims['imp_audit'])->toBe($outcome->auditId())
        ->and($claims['imp_mode'])->toBe('read_only');
});

it('carries the mode so a foreign resource server can enforce it', function (): void {
    // The reason the mode is a claim: our middleware cannot reach a service that only sees
    // the bearer token.
    foreach (['read_only', 'limited', 'full'] as $mode) {
        $outcome = Impersonator::enter($this->target, mode: $mode);

        expect(decodeClaims((string) $outcome->credential?->secret())['imp_mode'])->toBe($mode);

        Impersonator::leave();
    }
});

it('gives the token a short TTL independent of the app setting', function (): void {
    config()->set('jwt.ttl', 60 * 24);
    config()->set('laranail.impersonator.adapters.jwt.ttl', 5);

    $outcome = Impersonator::enter($this->target);
    $claims = decodeClaims((string) $outcome->credential?->secret());

    expect($claims['exp'] - $claims['iat'])->toBeLessThanOrEqual(5 * 60 + 2);
});

it('restores the application TTL after minting', function (): void {
    // `setTTL` is global state on the factory; leaving it changed would shorten every token
    // the application issues for the rest of the request.
    config()->set('jwt.ttl', 120);
    config()->set('laranail.impersonator.adapters.jwt.ttl', 5);

    Impersonator::enter($this->target);

    expect(app('tymon.jwt.auth')->factory()->getTTL())->toBe(120);
});

it('stores only a digest of the token on the audit row', function (): void {
    $outcome = Impersonator::enter($this->target);
    $secret = (string) $outcome->credential?->secret();

    $row = app(AuditStore::class)->find($outcome->auditId());

    expect($row->credentialHash)->toBe(hash('sha256', $secret))
        ->and(json_encode($row->toArray()))->not->toContain($secret);
});

it('reports revoke as false, because a JWT cannot be un-issued from the audit row alone', function (): void {
    // Claiming to have revoked a credential that will keep working until it expires would be
    // worse than admitting the limitation.
    $outcome = Impersonator::enter($this->target);
    $session = app(AuditStore::class)->find($outcome->auditId());

    expect(Impersonator::adapter('jwt')->revoke($session))->toBeFalse();
});

it('blacklists a token the caller still holds', function (): void {
    $outcome = Impersonator::enter($this->target);
    $adapter = Impersonator::adapter('jwt');

    expect($adapter)->toBeInstanceOf(JwtAdapter::class)
        ->and($adapter->blacklistEnabled())->toBeTrue()
        ->and($adapter->blacklist((string) $outcome->credential?->secret()))->toBeTrue();
});

it('reports false from blacklist when the blacklist is disabled', function (): void {
    config()->set('jwt.blacklist_enabled', false);
    $outcome = Impersonator::enter($this->target);

    $adapter = Impersonator::adapter('jwt');

    expect($adapter->blacklistEnabled())->toBeFalse()
        ->and($adapter->blacklist((string) $outcome->credential?->secret()))->toBeFalse();
});

it('does not throw when leaving', function (): void {
    Impersonator::enter($this->target);

    expect(fn () => Impersonator::leave())->not->toThrow(Throwable::class);
});

it('records the adapter on the audit row', function (): void {
    $outcome = Impersonator::enter($this->target);

    expect($outcome->session->adapter)->toBe('jwt');
});
