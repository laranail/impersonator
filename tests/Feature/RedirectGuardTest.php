<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Laravel\Support\RedirectGuard;

function guard(): RedirectGuard
{
    return app(RedirectGuard::class);
}

it('accepts an ordinary relative path', function (string $path): void {
    expect(guard()->isSafe($path))->toBeTrue();
})->with([
    '/',
    '/dashboard',
    '/orders/17/edit',
    '/search?q=hello&page=2',
    '/page#section',
]);

it('rejects a protocol-relative path that looks relative', function (string $path): void {
    // Every one of these starts with a slash, which is why a naive
    // str_starts_with('/') check is not enough on its own.
    expect(guard()->isSafe($path))->toBeFalse();
})->with([
    '//evil.example',
    '///evil.example',
    '/\\evil.example',     // browsers normalise the backslash to a slash
    '/\\/evil.example',
    "/\t/evil.example",
]);

it('rejects an absolute url by default', function (string $url): void {
    expect(guard()->isSafe($url))->toBeFalse();
})->with([
    'https://evil.example/phish',
    'http://evil.example',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'file:///etc/passwd',
    'HTTPS://EVIL.EXAMPLE',
]);

it('rejects control characters and whitespace inside a target', function (string $url): void {
    expect(guard()->isSafe($url))->toBeFalse();
})->with([
    "/dash\nboard",
    "/dash\rboard",
    "/dash\x00board",
    "https://evil.example\n",
]);

it('rejects an empty or blank target', function (): void {
    expect(guard()->isSafe(''))->toBeFalse()
        ->and(guard()->isSafe('   '))->toBeFalse();
});

it('allows an absolute url only when the host is explicitly allowlisted', function (): void {
    config()->set('laranail.impersonator.redirects.allow_absolute', true);
    config()->set('laranail.impersonator.redirects.allowed_hosts', ['app.example.com']);

    expect(guard()->isSafe('https://app.example.com/dashboard'))->toBeTrue()
        ->and(guard()->isSafe('https://evil.example/dashboard'))->toBeFalse();
});

it('matches allowlisted hosts exactly, never by suffix', function (string $url): void {
    // `allowed_hosts = ['example.com']` matching `evil-example.com` or
    // `example.com.attacker.tld` is how a host allowlist usually fails.
    config()->set('laranail.impersonator.redirects.allow_absolute', true);
    config()->set('laranail.impersonator.redirects.allowed_hosts', ['example.com']);

    expect(guard()->isSafe($url))->toBeFalse();
})->with([
    'https://evil-example.com/',
    'https://example.com.attacker.tld/',
    'https://sub.example.com/',
    'https://example.com.evil/',
]);

it('rejects an allowlisted host reached with embedded credentials', function (): void {
    // `https://example.com@evil.example` gets past a reader skimming the start
    // of a URL; the actual host is evil.example.
    config()->set('laranail.impersonator.redirects.allow_absolute', true);
    config()->set('laranail.impersonator.redirects.allowed_hosts', ['example.com']);

    expect(guard()->isSafe('https://example.com@evil.example/'))->toBeFalse()
        ->and(guard()->isSafe('https://user:pass@example.com/'))->toBeFalse();
});

it('rejects a non-http scheme even for an allowlisted host', function (): void {
    config()->set('laranail.impersonator.redirects.allow_absolute', true);
    config()->set('laranail.impersonator.redirects.allowed_hosts', ['example.com']);

    expect(guard()->isSafe('ftp://example.com/'))->toBeFalse()
        ->and(guard()->isSafe('javascript://example.com/%0aalert(1)'))->toBeFalse();
});

it('matches an allowlisted host case-insensitively', function (): void {
    config()->set('laranail.impersonator.redirects.allow_absolute', true);
    config()->set('laranail.impersonator.redirects.allowed_hosts', ['App.Example.COM']);

    expect(guard()->isSafe('https://app.example.com/x'))->toBeTrue();
});

it('falls back to the configured destination rather than failing the request', function (): void {
    config()->set('laranail.impersonator.redirects.after_leave', '/admin');

    expect(guard()->afterLeave('https://evil.example'))->toBe('/admin')
        ->and(guard()->afterLeave(null))->toBe('/admin')
        ->and(guard()->afterLeave('/reports'))->toBe('/reports');
});

it('validates the configured fallback too', function (): void {
    // Otherwise a misconfigured default would be the one target that bypassed
    // the check entirely.
    config()->set('laranail.impersonator.redirects.after_leave', '//evil.example');

    expect(guard()->afterLeave(null))->toBe('/');
});

it('uses the enter destination for enter', function (): void {
    config()->set('laranail.impersonator.redirects.after_enter', '/welcome');

    expect(guard()->afterEnter(null))->toBe('/welcome')
        ->and(guard()->afterEnter('/orders'))->toBe('/orders');
});

it('ignores a non-array allowed_hosts config', function (): void {
    config()->set('laranail.impersonator.redirects.allow_absolute', true);
    config()->set('laranail.impersonator.redirects.allowed_hosts', 'example.com');

    expect(guard()->isSafe('https://example.com/'))->toBeFalse();
});
