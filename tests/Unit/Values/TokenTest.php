<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Values\Token;

function makeToken(string $plaintext = 'super-secret-plaintext', int $ttl = 60): Token
{
    return new Token(
        plaintext: $plaintext,
        hash: hash('sha256', $plaintext),
        expiresAt: (new DateTimeImmutable('2026-01-01 00:00:00'))->modify("+{$ttl} seconds"),
    );
}

it('exposes the plaintext only through an explicit accessor', function (): void {
    expect(makeToken()->plaintext())->toBe('super-secret-plaintext');
});

it('keeps the plaintext out of its string form', function (): void {
    // The usual way a secret reaches a log file is an exception trace or a
    // stringified object, not a deliberate write.
    expect((string) makeToken())->not->toContain('super-secret-plaintext');
});

it('keeps the plaintext out of its debug form', function (): void {
    $debug = makeToken()->__debugInfo();

    expect($debug['plaintext'])->toBe('[redacted]')
        ->and(print_r($debug, true))->not->toContain('super-secret-plaintext');
});

it('does not leak the plaintext when serialized for a log context', function (): void {
    expect(json_encode(makeToken()->__debugInfo()))->not->toContain('super-secret-plaintext');
});

it('reports expiry against a supplied clock', function (): void {
    $token = makeToken(ttl: 60);

    expect($token->isExpiredAt(new DateTimeImmutable('2026-01-01 00:00:30')))->toBeFalse()
        ->and($token->isExpiredAt(new DateTimeImmutable('2026-01-01 00:01:01')))->toBeTrue();
});

it('stores a digest that matches its plaintext', function (): void {
    $token = makeToken();

    expect($token->hash)->toBe(hash('sha256', $token->plaintext()))
        ->and($token->hash)->toHaveLength(64);
});
