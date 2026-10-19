<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Support\Redactor;
use Simtabi\Laranail\Package\Tools\Testing\TestCredentials;

function redactor(): Redactor
{
    return Redactor::for(['password', 'token', 'secret', 'authorization', 'card', 'cvv']);
}

it('redacts a matching key', function (): void {
    expect(Redactor::PLACEHOLDER)->toBe('[redacted]');

    expect(redactor()->scrub(['password' => TestCredentials::password('redactor')]))
        ->toBe(['password' => Redactor::PLACEHOLDER]);
});

it('matches as a case-insensitive substring', function (string $key): void {
    // The configured list must not have to enumerate every spelling an application
    // might use for the same secret.
    expect(redactor()->scrub([$key => TestCredentials::password('redactor')])[$key])->toBe(Redactor::PLACEHOLDER);
})->with([
    'password_confirmation',
    'PASSWORD',
    'currentPassword',
    'current-password',
    'api_token',
    'Authorization',
    'card_number',
    'CVV',
]);

it('redacts recursively', function (): void {
    // A password nested inside a JSON body is still a password; flat key checking is
    // the usual reason redaction misses one.
    $scrubbed = redactor()->scrub([
        'user' => [
            'name'        => 'Ada',
            'credentials' => ['password' => TestCredentials::password('redactor'), 'token' => 'abc'],
        ],
    ]);

    expect($scrubbed['user']['name'])->toBe('Ada')
        ->and($scrubbed['user']['credentials']['password'])->toBe(Redactor::PLACEHOLDER)
        ->and($scrubbed['user']['credentials']['token'])->toBe(Redactor::PLACEHOLDER);
});

it('replaces a sensitive subtree wholesale', function (): void {
    // A sensitive key holding an array is still a sensitive key.
    expect(redactor()->scrub(['secret' => ['a' => 1, 'b' => 2]])['secret'])->toBe(Redactor::PLACEHOLDER);
});

it('keeps the key rather than removing it', function (): void {
    // A silently absent key reads as a field that was never sent, which changes what
    // the trail appears to say.
    expect(redactor()->scrub(['password' => 'x']))->toHaveKey('password');
});

it('leaves non-sensitive values untouched', function (): void {
    expect(redactor()->scrub(['email' => 'ada@example.com', 'age' => 36, 'ok' => true]))
        ->toBe(['email' => 'ada@example.com', 'age' => 36, 'ok' => true]);
});

it('reduces objects to a type label rather than serialising them', function (): void {
    // An uploaded file or a model in a payload would otherwise pull its whole graph
    // into the trail.
    $scrubbed = redactor()->scrub(['thing' => new stdClass]);

    expect($scrubbed['thing'])->toBe('[object stdClass]');
});

it('bounds recursion so a deep structure cannot overflow the stack', function (): void {
    $deep = ['v' => 'leaf'];

    for ($i = 0; $i < 40; $i++) {
        $deep = ['nested' => $deep];
    }

    expect(json_encode(redactor()->scrub($deep)))->toContain('_truncated');
});

it('redacts nothing when configured with no keys', function (): void {
    expect(Redactor::for([])->scrub(['password' => TestCredentials::password('redactor')]))
        ->toBe(['password' => TestCredentials::password('redactor')]);
});

it('ignores blank entries in the configured list', function (): void {
    expect(Redactor::for(['', '   ', 'password'])->scrub(['email' => 'a@b.c', 'password' => 'x']))
        ->toBe(['email' => 'a@b.c', 'password' => Redactor::PLACEHOLDER]);
});

it('normalises integer keys to strings', function (): void {
    expect(redactor()->scrub([0 => 'a', 1 => 'b']))->toBe(['0' => 'a', '1' => 'b']);
});
