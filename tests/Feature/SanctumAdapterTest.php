<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Database\Schema\Blueprint;
use Laravel\Sanctum\SanctumServiceProvider;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\ApiUser;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\PlainUser;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Enums\CredentialType;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;

uses()->group('sanctum');

beforeEach(function (): void {
    $this->app->register(SanctumServiceProvider::class);

    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    Schema::create('personal_access_tokens', function (Blueprint $table): void {
        $table->id();
        $table->morphs('tokenable');
        $table->string('name');
        $table->string('token', 64)->unique();
        $table->text('abilities')->nullable();
        $table->timestamp('last_used_at')->nullable();
        $table->timestamp('expires_at')->nullable();
        $table->timestamps();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => ApiUser::class]);
    config()->set('auth.providers.users.model', ApiUser::class);
    config()->set('laranail.impersonator.adapter', 'sanctum');
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 10);

    $this->admin = ApiUser::create(['name' => 'Admin']);
    $this->target = ApiUser::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

it('reports itself available when sanctum is installed', function (): void {
    expect(Impersonator::adapter('sanctum')->isAvailable())->toBeTrue();
});

it('issues a bearer credential for the target', function (): void {
    // For an API there is no session to switch, so impersonation means issuing a
    // short-lived credential *for the target*.
    $outcome = Impersonator::enter($this->target);

    expect($outcome->credential?->type)->toBe(CredentialType::SanctumToken)
        ->and($outcome->credential?->hasSecret())->toBeTrue()
        ->and($outcome->credential?->secret())->toBeString();
});

it('scopes the token to a single impersonated ability, not everything', function (): void {
    // Not `*`: the token cannot do everything the target's own tokens can, and an app can
    // check for this ability to refuse what it considers off-limits.
    Impersonator::enter($this->target);

    $token = PersonalAccessToken::query()->firstOrFail();

    expect($token->abilities)->toBe(['impersonated'])
        ->and($token->can('impersonated'))->toBeTrue()
        ->and($token->can('*'))->toBeFalse();
});

it('gives the token a short expiry independent of the app setting', function (): void {
    // A support credential and a user's own long-lived API token have nothing in common.
    config()->set('sanctum.expiration', 60 * 24 * 30);
    config()->set('laranail.impersonator.adapters.sanctum.expires_after', 5);

    $outcome = Impersonator::enter($this->target);

    expect($outcome->credential?->expiresAt?->getTimestamp())
        ->toBeLessThanOrEqual(now()->addMinutes(5)->getTimestamp() + 2)
        ->and(PersonalAccessToken::query()->firstOrFail()->expires_at)->not->toBeNull();
});

it('names the token after the audit row so a leak traces back to the operator', function (): void {
    $outcome = Impersonator::enter($this->target);

    expect(PersonalAccessToken::query()->firstOrFail()->name)
        ->toBe('impersonation:' . $outcome->auditId());
});

it('issues the token to the target, not the operator', function (): void {
    $outcome = Impersonator::enter($this->target);

    $token = PersonalAccessToken::query()->firstOrFail();

    expect((string) $token->tokenable_id)->toBe((string) $this->target->getKey())
        ->and($outcome->session->target->id)->toBe((string) $this->target->getKey());
});

it('stores only a digest of the credential on the audit row', function (): void {
    // The plaintext exists in one response and nowhere else.
    $outcome = Impersonator::enter($this->target);
    $secret = $outcome->credential?->secret();

    $row = app(AuditStore::class)->find($outcome->auditId());

    expect($row->credentialHash)->toBe(hash('sha256', (string) $secret))
        ->and(json_encode($row->toArray()))->not->toContain((string) $secret);
});

it('keeps the secret out of the audit projection entirely', function (): void {
    $outcome = Impersonator::enter($this->target);

    expect(json_encode($outcome->credential?->toAuditArray()))
        ->not->toContain((string) $outcome->credential?->secret());
});

it('deletes the token on leave', function (): void {
    Impersonator::enter($this->target);

    expect(PersonalAccessToken::query()->count())->toBe(1);

    Impersonator::leave();

    expect(PersonalAccessToken::query()->count())->toBe(0);
});

it('revokes immediately, unlike a session', function (): void {
    // A session can only be ended from inside itself; a token row can be deleted from
    // anywhere, so revocation here needs no next-request dependency.
    $outcome = Impersonator::enter($this->target);
    $session = app(AuditStore::class)->find($outcome->auditId());

    expect(Impersonator::adapter('sanctum')->revoke($session))->toBeTrue()
        ->and(PersonalAccessToken::query()->count())->toBe(0);
});

it('does not fail leaving when the token has already gone', function (): void {
    // Leave only de-escalates, so an already-expired or already-revoked token must not turn
    // leaving into an error.
    Impersonator::enter($this->target);
    PersonalAccessToken::query()->delete();

    expect(fn () => Impersonator::leave())->not->toThrow(Throwable::class);
});

it('impersonates a target that does not use the HasApiTokens trait', function (): void {
    // Sanctum's trait carries no `@phpstan-require-implements`, and Laravel's default User uses
    // it *without* the contract — so requiring either would refuse the most common setup there
    // is. Writing through Sanctum's own model instead means any Eloquent target works.
    config()->set('laranail.impersonator.targets.allowlist', [
        'user'  => ApiUser::class,
        'plain' => PlainUser::class,
    ]);

    $plain = PlainUser::create(['name' => 'Plain']);

    $outcome = Impersonator::enter($plain);

    expect($outcome->credential?->hasSecret())->toBeTrue()
        ->and(PersonalAccessToken::query()->firstOrFail()->tokenable_type)
        ->toBe($plain->getMorphClass());
});

it('issues a token in the wire format sanctum itself parses', function (): void {
    // `{id}|{plaintext}`, with the stored value the SHA-256 of the plaintext half — the shape
    // Sanctum's own guard splits on, so an issued credential authenticates normally.
    $outcome = Impersonator::enter($this->target);
    $secret = (string) $outcome->credential?->secret();

    [$id, $plaintext] = explode('|', $secret, 2);
    $row = PersonalAccessToken::query()->firstOrFail();

    expect((string) $row->getKey())->toBe($id)
        ->and($row->token)->toBe(hash('sha256', $plaintext))
        ->and(PersonalAccessToken::findToken($secret)?->getKey())->toBe($row->getKey());
});

it('records the audit row before issuing the credential', function (): void {
    // Same ordering rule as every other driver: an impersonation that happened without a
    // record of it is the outcome that must be impossible.
    $outcome = Impersonator::enter($this->target);

    expect(app(AuditStore::class)->find($outcome->auditId()))->not->toBeNull()
        ->and($outcome->session->adapter)->toBe('sanctum');
});
