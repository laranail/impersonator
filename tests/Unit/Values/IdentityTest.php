<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Exceptions\InvalidIdentity;

it('rejects an empty type', function (): void {
    Identity::of('  ', 1);
})->throws(InvalidIdentity::class);

it('rejects an empty id', function (): void {
    Identity::of('user', '');
})->throws(InvalidIdentity::class);

it('matches the same actor across id types', function (): void {
    // A route parameter arrives as "7" while Eloquent hands back 7. Treating
    // those as different actors is precisely how a self-impersonation check
    // gets bypassed, so the comparison is loose on the id's PHP type.
    expect(Identity::of('user', 7)->is(Identity::of('user', '7')))->toBeTrue();
});

it('does not match across types', function (): void {
    expect(Identity::of('user', 7)->is(Identity::of('admin', 7)))->toBeFalse()
        ->and(Identity::of('user', 7)->isNot(Identity::of('admin', 7)))->toBeTrue();
});

it('builds a stable key', function (): void {
    expect(Identity::of('user', 7)->key())->toBe('user:7')
        ->and((string) Identity::of('user', 7))->toBe('user:7');
});

it('round-trips through an array', function (): void {
    $identity = Identity::of('user', 42, 'Ada');

    expect(Identity::fromArray($identity->toArray()))->toEqual($identity);
});

it('carries a label without affecting equality', function (): void {
    $bare = Identity::of('user', 1);
    $labelled = $bare->withLabel('Ada');

    expect($labelled->label)->toBe('Ada')
        ->and($labelled->is($bare))->toBeTrue()
        ->and($bare->label)->toBeNull();
});
