<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;
use Simtabi\Laranail\Impersonator\Core\Values\Guards;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Tokens\AcceptUrlBuilder;

function tokenRequest(?string $tenantId = null): ImpersonationRequest
{
    return new ImpersonationRequest(
        impersonator: Identity::of('user', 1),
        target: Identity::of('user', 2),
        mode: Mode::full(),
        guards: Guards::both('web'),
        driver: 'token',
        adapter: 'session',
        tenantId: $tenantId,
    );
}

function builder(): AcceptUrlBuilder
{
    return app(AcceptUrlBuilder::class);
}

beforeEach(function (): void {
    config()->set('app.url', 'https://admin.example.com');
});

it('builds a domain-strategy URL from the base domain', function (): void {
    config()->set('laranail.impersonator.urls.strategy', 'domain');
    config()->set('laranail.impersonator.urls.base_domain', 'tenant.example.com');

    expect(builder()->build(tokenRequest(), 'abc123'))
        ->toBe('https://tenant.example.com/impersonator/accept/abc123');
});

it('falls back to the app host when no base domain is configured', function (): void {
    config()->set('laranail.impersonator.urls.strategy', 'domain');
    config()->set('laranail.impersonator.urls.base_domain', null);

    expect(builder()->build(tokenRequest(), 'abc123'))
        ->toBe('https://admin.example.com/impersonator/accept/abc123');
});

it('builds a subdomain-strategy URL from the tenant key', function (): void {
    config()->set('laranail.impersonator.urls.strategy', 'subdomain');
    config()->set('laranail.impersonator.urls.base_domain', 'example.com');

    expect(builder()->build(tokenRequest('acme'), 'abc123'))
        ->toBe('https://acme.example.com/impersonator/accept/abc123');
});

it('refuses the subdomain strategy without a tenant', function (): void {
    // Neither half is guessable, so this fails rather than building a link to the wrong host.
    config()->set('laranail.impersonator.urls.strategy', 'subdomain');
    config()->set('laranail.impersonator.urls.base_domain', 'example.com');

    expect(fn (): string => builder()->build(tokenRequest(), 'abc123'))
        ->toThrow(ImpersonationException::class, 'initialized tenant');
});

it('builds a path-strategy URL from the tenant key', function (): void {
    config()->set('laranail.impersonator.urls.strategy', 'path');
    config()->set('laranail.impersonator.urls.base_domain', 'example.com');

    expect(builder()->build(tokenRequest('acme'), 'abc123'))
        ->toBe('https://example.com/acme/impersonator/accept/abc123');
});

it('prefers an explicit path prefix over the tenant key', function (): void {
    config()->set('laranail.impersonator.urls.strategy', 'path');
    config()->set('laranail.impersonator.urls.base_domain', 'example.com');
    config()->set('laranail.impersonator.urls.path_prefix', 'app');

    expect(builder()->build(tokenRequest('acme'), 'abc123'))
        ->toBe('https://example.com/app/impersonator/accept/abc123');
});

it('honours the scheme', function (): void {
    config()->set('laranail.impersonator.urls.base_domain', 'tenant.test');
    config()->set('laranail.impersonator.urls.scheme', 'http');

    expect(builder()->build(tokenRequest(), 'abc'))->toStartWith('http://tenant.test/');
});

it('ignores an unrecognised scheme rather than emitting it', function (): void {
    config()->set('laranail.impersonator.urls.base_domain', 'tenant.test');
    config()->set('laranail.impersonator.urls.scheme', 'gopher');

    expect(builder()->build(tokenRequest(), 'abc'))->toStartWith('https://');
});

it('appends a non-default port', function (): void {
    config()->set('laranail.impersonator.urls.base_domain', 'tenant.test');
    config()->set('laranail.impersonator.urls.port', 8443);

    expect(builder()->build(tokenRequest(), 'abc'))->toStartWith('https://tenant.test:8443/');
});

it('omits the port when it is the scheme default', function (): void {
    // `https://host:443` is legal but differs textually from the app's own links, and an
    // exact-match host allowlist elsewhere would then disagree with it.
    config()->set('laranail.impersonator.urls.base_domain', 'tenant.test');
    config()->set('laranail.impersonator.urls.port', 443);

    expect(builder()->build(tokenRequest(), 'abc'))->toBe(
        'https://tenant.test/impersonator/accept/abc',
    );
});

it('url-encodes the token', function (): void {
    config()->set('laranail.impersonator.urls.base_domain', 'tenant.test');

    expect(builder()->build(tokenRequest(), 'a+b/c=='))
        ->toContain(rawurlencode('a+b/c=='));
});

it('substitutes the token mid-path when the pattern puts it there', function (): void {
    // So an application can use `accept/{token}/confirm` without this needing to know.
    config()->set('laranail.impersonator.urls.base_domain', 'tenant.test');
    config()->set('laranail.impersonator.routes.accept_path', 'accept/{token}/confirm');

    expect(builder()->build(tokenRequest(), 'abc'))
        ->toBe('https://tenant.test/impersonator/accept/abc/confirm');
});

it('appends the token when the pattern has no placeholder', function (): void {
    config()->set('laranail.impersonator.urls.base_domain', 'tenant.test');
    config()->set('laranail.impersonator.routes.accept_path', 'handoff');

    expect(builder()->build(tokenRequest(), 'abc'))
        ->toBe('https://tenant.test/impersonator/handoff/abc');
});

it('honours a custom resolver above everything else', function (): void {
    // The documented escape hatch, and a real one: tenant addressing is the part of a
    // multi-tenant app most likely to be bespoke.
    config()->set('laranail.impersonator.urls.base_domain', 'tenant.test');

    Impersonator::resolveAcceptUrlUsing(
        static fn (ImpersonationRequest $request, string $token): string => 'https://custom.test/x/'.$token,
    );

    expect(builder()->build(tokenRequest(), 'abc'))->toBe('https://custom.test/x/abc');
});

it('rejects a resolver that returns something unusable', function (): void {
    Impersonator::resolveAcceptUrlUsing(static fn (): ?string => null);

    expect(fn (): string => builder()->build(tokenRequest(), 'abc'))
        ->toThrow(ImpersonationException::class, 'non-empty absolute URL');
});
