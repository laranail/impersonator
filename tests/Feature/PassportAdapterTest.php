<?php

declare(strict_types=1);

use Laravel\Passport\Token;
use Laravel\Passport\Passport;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Laravel\Passport\PassportServiceProvider;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Enums\CredentialType;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\PassportUser;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;

uses()->group('passport');

beforeEach(function (): void {
    $this->app->register(PassportServiceProvider::class);

    Schema::create('users', function ($table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    // Passport's own migrations, run from its published path so the suite exercises the real
    // schema rather than a hand-written approximation of it.
    $this->loadMigrationsFrom(dirname(__DIR__, 2) . '/vendor/laravel/passport/database/migrations');
    $this->artisan('migrate', ['--database' => 'testing'])->run();

    // Passport signs tokens with an RSA keypair, so one has to exist. Generated per run into
    // a temp directory rather than the app's storage path, so the suite leaves nothing behind.
    $keys = sys_get_temp_dir() . '/impersonator-passport-keys-' . bin2hex(random_bytes(6));
    mkdir($keys, 0o700, true);
    Passport::loadKeysFrom($keys);
    $this->artisan('passport:keys', ['--force' => true])->run();

    // Personal access tokens need a personal access client to exist. An installation without
    // one cannot issue any, which is why the adapter names this in its failure message.
    $this->artisan('passport:client', [
        '--personal'       => true,
        '--name'           => 'Impersonation tests',
        '--provider'       => 'users',
        '--no-interaction' => true,
    ])->run();

    config()->set('laranail.impersonator.targets.allowlist', ['user' => PassportUser::class]);
    config()->set('auth.providers.users', ['driver' => 'eloquent', 'model' => PassportUser::class]);
    // Passport resolves a model's provider by looking for a guard whose driver is `passport`,
    // so an application without one cannot issue tokens at all.
    config()->set('auth.guards.api', ['driver' => 'passport', 'provider' => 'users']);
    config()->set('laranail.impersonator.adapter', 'passport');
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 10);

    $this->admin = PassportUser::create(['name' => 'Admin']);
    $this->target = PassportUser::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

it('reports itself available when passport is installed', function (): void {
    expect(Impersonator::adapter('passport')->isAvailable())->toBeTrue();
});

it('issues an access token for the target', function (): void {
    $outcome = Impersonator::enter($this->target);

    expect($outcome->credential?->type)->toBe(CredentialType::PassportToken)
        ->and($outcome->credential?->hasSecret())->toBeTrue();
});

it('never issues a refresh token', function (): void {
    // A refresh token would let an impersonation renew itself indefinitely, outliving both
    // its audit row and the operator's authority to hold it.
    $outcome = Impersonator::enter($this->target);

    expect($outcome->credential?->metadata['refresh_token'])->toBeFalse()
        ->and(DB::table('oauth_refresh_tokens')->count())->toBe(0);
});

it('scopes the token to a single impersonated scope', function (): void {
    Impersonator::enter($this->target);

    expect(Token::query()->firstOrFail()->scopes)->toBe(['impersonated']);
});

it('names the token after the audit row', function (): void {
    $outcome = Impersonator::enter($this->target);

    expect(Token::query()->firstOrFail()->name)->toBe('impersonation:' . $outcome->auditId());
});

it('shortens the expiry without shortening every other token the app issues', function (): void {
    config()->set('laranail.impersonator.adapters.passport.expires_after', 5);

    $outcome = Impersonator::enter($this->target);

    expect($outcome->credential?->expiresAt?->getTimestamp())
        ->toBeLessThanOrEqual(now()->addMinutes(5)->getTimestamp() + 2)
        ->and(Token::query()->firstOrFail()->expires_at)->not->toBeNull();
});

it('stores only a digest of the credential on the audit row', function (): void {
    $outcome = Impersonator::enter($this->target);
    $secret = (string) $outcome->credential?->secret();

    $row = app(AuditStore::class)->find($outcome->auditId());

    expect($row->credentialHash)->toBe(hash('sha256', $secret))
        ->and(json_encode($row->toArray()))->not->toContain($secret);
});

it('marks the token revoked on leave rather than deleting it', function (): void {
    // The OAuth record of the grant survives for audit while the credential stops working.
    Impersonator::enter($this->target);

    Impersonator::leave();

    $token = Token::query()->firstOrFail();

    expect($token->revoked)->toBeTrue()
        ->and(Token::query()->count())->toBe(1);
});

it('revokes immediately, and passport refuses it thereafter', function (): void {
    $outcome = Impersonator::enter($this->target);
    $session = app(AuditStore::class)->find($outcome->auditId());

    expect(Impersonator::adapter('passport')->revoke($session))->toBeTrue()
        ->and(Token::query()->firstOrFail()->revoked)->toBeTrue();
});

it('does not fail leaving when the token has already gone', function (): void {
    Impersonator::enter($this->target);
    Token::query()->delete();

    expect(fn () => Impersonator::leave())->not->toThrow(Throwable::class);
});

it('records the adapter on the audit row', function (): void {
    expect(Impersonator::enter($this->target)->session->adapter)->toBe('passport');
});
