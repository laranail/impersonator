<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Eloquent\Relations\Relation;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\Secret;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\NotAModel;
use Simtabi\Laranail\Impersonator\Core\Exceptions\InvalidIdentity;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
});

function resolver(): IdentityResolver
{
    return app(IdentityResolver::class);
}

it('reduces a model to its alias and key', function (): void {
    $user = User::create(['name' => 'Ada']);

    $identity = resolver()->fromUser($user);

    expect($identity->type)->toBe('user')
        ->and($identity->id)->toBe($user->getKey())
        ->and($identity->label)->toBe('Ada');
});

it('refuses to build an identity for an unsaved model', function (): void {
    // A row pointing at a null key is a row pointing at nothing.
    resolver()->fromUser(new User(['name' => 'Ada']));
})->throws(InvalidIdentity::class, 'unsaved');

it('resolves an allowlisted identity back to its model', function (): void {
    $user = User::create(['name' => 'Ada']);

    expect(resolver()->toUser(Identity::of('user', $user->getKey()))?->getKey())->toBe($user->getKey());
});

it('refuses to load a class outside the allowlist', function (): void {
    // The control that blocks arbitrary class injection: an endpoint naming any
    // model must not get that model loaded.
    expect(resolver()->toUser(Identity::of(Secret::class, 1)))->toBeNull()
        ->and(resolver()->isAllowlisted(Secret::class))->toBeFalse();
});

it('does not touch the database for a non-allowlisted type', function (): void {
    // `secrets` has no table here, so a query would error rather than return
    // null — which is what proves the check runs before resolution.
    expect(resolver()->toUser(Identity::of('secret', 1)))->toBeNull();
});

it('accepts either the alias or the class when checking the allowlist', function (): void {
    expect(resolver()->isAllowlisted('user'))->toBeTrue()
        ->and(resolver()->isAllowlisted(User::class))->toBeTrue()
        ->and(resolver()->classFor(User::class))->toBe(User::class)
        ->and(resolver()->classFor('user'))->toBe(User::class);
});

it('denies every target when the allowlist is empty', function (): void {
    config()->set('laranail.impersonator.targets.allowlist', []);

    expect(resolver()->allowlist())->toBe([])
        ->and(resolver()->isAllowlisted(User::class))->toBeFalse();
});

it('drops allowlist entries that are not installed Eloquent models', function (): void {
    config()->set('laranail.impersonator.targets.allowlist', [
        'user'  => User::class,
        'ghost' => 'App\\Models\\Removed',
        'plain' => NotAModel::class,
    ]);

    expect(resolver()->allowlist())->toBe(['user' => User::class]);
});

it('survives an allowlist that is not an array', function (): void {
    config()->set('laranail.impersonator.targets.allowlist', 'nonsense');

    expect(resolver()->allowlist())->toBe([]);
});

it('prefers a globally enforced morph alias over the class name', function (): void {
    // Otherwise one type ends up with two spellings across the audit rows.
    config()->set('laranail.impersonator.targets.allowlist', [Secret::class]);
    Relation::morphMap(['vault' => Secret::class]);

    expect(resolver()->aliasFor(Secret::class))->toBe('vault');
});

it('falls back to the class name when no alias is registered', function (): void {
    config()->set('laranail.impersonator.targets.allowlist', []);
    Relation::morphMap([], merge: false);

    expect(resolver()->aliasFor(Secret::class))->toBe(Secret::class);
});

it('reports a soft-deleted target as trashed', function (): void {
    $user = User::create(['name' => 'Ada']);
    $user->delete();

    expect(resolver()->isTrashed($user->fresh() ?? $user))->toBeTrue();
});

it('reports a live target as not trashed', function (): void {
    expect(resolver()->isTrashed(User::create(['name' => 'Ada'])))->toBeFalse();
});

it('excludes a soft-deleted target from resolution unless asked', function (): void {
    $user = User::create(['name' => 'Ada']);
    $user->delete();

    $identity = Identity::of('user', $user->getKey());

    expect(resolver()->toUser($identity))->toBeNull()
        ->and(resolver()->toUser($identity, withTrashed: true)?->getKey())->toBe($user->getKey());
});

it('resolves an operator whose type is not in the target allowlist', function (): void {
    // The asymmetry that matters: the allowlist governs what may be *impersonated*,
    // because the target arrives as request input. An operator's identity comes from the
    // authenticated session, so an Admin model that enters as User must not have to be
    // listed among the accounts that can be impersonated — that would be backwards.
    config()->set('laranail.impersonator.targets.allowlist', ['other' => Secret::class]);

    $operator = User::create(['name' => 'Operator']);
    $identity = resolver()->fromUser($operator);

    expect(resolver()->isAllowlisted($identity->type))->toBeFalse()
        ->and(resolver()->toUser($identity))->toBeNull()
        ->and(resolver()->resolveActor($identity)?->getKey())->toBe($operator->getKey());
});

it('still refuses to resolve an operator type that is not an Eloquent model', function (): void {
    expect(resolver()->resolveActor(Identity::of(NotAModel::class, 1)))->toBeNull()
        ->and(resolver()->resolveActor(Identity::of('not-a-registered-type', 1)))->toBeNull();
});

it('resolves a deactivated operator so the trail can still name them', function (): void {
    // An account disabled since the impersonation began must remain nameable, or the
    // record stops describing who acted.
    $operator = User::create(['name' => 'Operator']);
    $identity = resolver()->fromUser($operator);
    $operator->delete();

    expect(resolver()->resolveActor($identity)?->getKey())->toBe($operator->getKey());
});
