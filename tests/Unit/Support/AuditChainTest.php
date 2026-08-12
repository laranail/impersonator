<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Support\AuditChain;

function chain(string $key = 'a-long-random-key'): AuditChain
{
    return new AuditChain($key);
}

/** @return array<string, mixed> */
function facts(array $overrides = []): array
{
    return [
        'impersonator' => 'user:1',
        'target' => 'user:2',
        'mode' => 'full',
        'driver' => 'session',
        'adapter' => 'session',
        'guard_impersonator' => 'web',
        'guard_target' => 'web',
        'tenant_id' => null,
        'reason' => 'Ticket #1',
        'started_at' => 1_700_000_000,
        // Spread, not `+`: array union keeps the left-hand value, so `+ $overrides` would silently
        // ignore every override and quietly pass the tests that depend on them.
        ...$overrides,
    ];
}

it('produces a stable digest for the same input', function (): void {
    // Reproducibility is the whole contract: the digest is recomputed from a database row years
    // later, so anything unstable would report tampering where there was none.
    expect(chain()->digest(facts(), null))->toBe(chain()->digest(facts(), null));
});

it('does not depend on key order', function (): void {
    $reordered = array_reverse(facts(), preserve_keys: true);

    expect(chain()->digest($reordered, null))->toBe(chain()->digest(facts(), null));
});

it('changes when any fact changes', function (string $field, mixed $value): void {
    $tampered = facts();
    $tampered[$field] = $value;

    expect(chain()->digest($tampered, null))->not->toBe(chain()->digest(facts(), null));
})->with([
    ['impersonator', 'user:9'],
    ['target', 'user:9'],
    ['mode', 'read_only'],
    ['driver', 'token'],
    ['adapter', 'sanctum'],
    ['guard_target', 'admin'],
    ['tenant_id', 'acme'],
    ['reason', 'Ticket #2'],
    ['started_at', 1_700_000_001],
]);

it('distinguishes a null fact from an empty one', function (): void {
    // "No reason given" and "an empty reason" are different facts; collapsing them would let one
    // be edited into the other undetected.
    expect(chain()->digest(facts(['reason' => null]), null))
        ->not->toBe(chain()->digest(facts(['reason' => '']), null));
});

it('cannot be recomputed without the key', function (): void {
    // The reason this is an HMAC and not a bare hash: an attacker with write access to the table
    // knows the algorithm, and would otherwise just rewrite every digest after the row they edited.
    expect(chain('key-one')->digest(facts(), null))
        ->not->toBe(chain('key-two')->digest(facts(), null));
});

it('links each digest to its predecessor', function (): void {
    $first = chain()->digest(facts(), null);
    $second = chain()->digest(facts(['target' => 'user:3']), $first);

    // The same row chained off a different predecessor digests differently, which is what makes a
    // deletion in the middle detectable.
    expect(chain()->digest(facts(['target' => 'user:3']), 'some-other-hash'))->not->toBe($second);
});

it('verifies a matching row', function (): void {
    $hash = chain()->digest(facts(), null);

    expect(chain()->verify(facts(), null, $hash))->toBeTrue();
});

it('rejects an altered row', function (): void {
    $hash = chain()->digest(facts(), null);

    expect(chain()->verify(facts(['mode' => 'read_only']), null, $hash))->toBeFalse();
});

it('rejects a row whose predecessor changed', function (): void {
    // A deleted row shows up exactly here: the next row's recorded predecessor no longer matches.
    $hash = chain()->digest(facts(), 'the-real-predecessor');

    expect(chain()->verify(facts(), 'a-different-predecessor', $hash))->toBeFalse();
});

it('treats a missing predecessor as genesis', function (): void {
    expect(chain()->digest(facts(), null))->toBe(chain()->digest(facts(), AuditChain::GENESIS));
});

it('produces a hex sha256 digest', function (): void {
    expect(chain()->digest(facts(), null))->toHaveLength(64)
        ->toMatch('/^[0-9a-f]{64}$/');
});

it('canonicalises nested arrays deterministically', function (): void {
    $a = ['meta' => ['b' => 2, 'a' => 1]];
    $b = ['meta' => ['a' => 1, 'b' => 2]];

    expect(chain()->canonicalise($a))->toBe(chain()->canonicalise($b));
});

it('separates fields unambiguously', function (): void {
    // `a=1,b=` and `a=1,` must not collide — hence a separator no normalised value can contain.
    expect(chain()->canonicalise(['a' => '1', 'b' => '']))
        ->not->toBe(chain()->canonicalise(['a' => '1']));
});
