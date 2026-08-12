<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Tokens;

use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * Builds the URL that completes a cross-domain handoff.
 *
 * Three addressing strategies, because multi-tenant applications genuinely differ and
 * guessing wrong produces a link to the wrong host:
 *
 *  - `domain` — the tenant's own domain, resolved from the tenant record.
 *  - `subdomain` — `{tenant}.example.com`, from a configured base domain.
 *  - `path` — `example.com/{tenant}/…`, for path-identified tenancy.
 *
 * `Impersonator::resolveAcceptUrlUsing()` overrides all of it, which is the documented
 * escape hatch for a scheme config cannot express — and a real one, since tenant
 * addressing is the part of a multi-tenant app most likely to be bespoke.
 *
 * The token appears in the returned URL and nowhere else. It is never logged, never put in
 * an event, and never stored: only its digest reaches the database, so this string is the
 * one and only copy.
 */
final readonly class AcceptUrlBuilder
{
    public function __construct(
        private Settings $settings,
        private ImpersonationManager $manager,
    ) {}

    public function build(ImpersonationRequest $request, string $token): string
    {
        // The application's own resolver wins outright.
        if ($this->manager->hasAcceptUrlResolver()) {
            return $this->manager->callAcceptUrlResolver($request, $token);
        }

        $strategy = $this->settings->enum('urls.strategy', ['domain', 'subdomain', 'path'], 'domain');

        return match ($strategy) {
            'subdomain' => $this->subdomain($request, $token),
            'path' => $this->path($request, $token),
            default => $this->domain($token),
        };
    }

    private function domain(string $token): string
    {
        $host = $this->tenantDomain();

        if ($host === null) {
            throw new ImpersonationException(
                'Could not resolve a domain for the accept URL. Set impersonator.urls.base_domain, '
                . 'switch impersonator.urls.strategy, or register '
                . 'Impersonator::resolveAcceptUrlUsing() for a custom addressing scheme.',
            );
        }

        return $this->assemble($host, $this->acceptPath($token));
    }

    private function subdomain(ImpersonationRequest $request, string $token): string
    {
        $base = $this->settings->nullableString('urls.base_domain');
        $tenant = $request->tenantId;

        if ($base === null || $tenant === null) {
            throw new ImpersonationException(
                'The subdomain strategy needs both impersonator.urls.base_domain and an '
                . 'initialized tenant. Neither is guessable, so this fails rather than '
                . 'building a link to the wrong host.',
            );
        }

        return $this->assemble($tenant . '.' . $base, $this->acceptPath($token));
    }

    private function path(ImpersonationRequest $request, string $token): string
    {
        $base = $this->settings->nullableString('urls.base_domain') ?? $this->currentHost();
        $prefix = $this->settings->nullableString('urls.path_prefix') ?? $request->tenantId;

        if ($base === null) {
            throw new ImpersonationException('The path strategy needs impersonator.urls.base_domain.');
        }

        $path = $prefix === null
            ? $this->acceptPath($token)
            : trim($prefix, '/') . '/' . $this->acceptPath($token);

        return $this->assemble($base, $path);
    }

    /**
     * The tenant's domain, when a tenancy package is installed and exposes one.
     *
     * Kept behind method_exists so tenancy stays an optional driver: the shape probed here
     * is stancl's, but anything exposing a `domains` relation works.
     */
    private function tenantDomain(): ?string
    {
        if (! function_exists('tenant')) {
            return $this->settings->nullableString('urls.base_domain') ?? $this->currentHost();
        }
        $tenant = tenant();
        if (is_object($tenant)) {
            $domain = $this->firstDomainOf($tenant);

            if ($domain !== null) {
                return $domain;
            }
        }

        return $this->settings->nullableString('urls.base_domain') ?? $this->currentHost();
    }

    /**
     * The tenant's first domain, probed defensively.
     *
     * The shape is stancl's `domains()` relation, but nothing here is typed against it — the
     * package is optional, so every step is checked rather than assumed.
     */
    private function firstDomainOf(object $tenant): ?string
    {
        if (! method_exists($tenant, 'domains')) {
            return null;
        }

        try {
            $relation = $tenant->domains();

            if (! is_object($relation) || ! method_exists($relation, 'first')) {
                return null;
            }

            $first = $relation->first();
            $domain = is_object($first) && property_exists($first, 'domain') ? $first->domain : null;

            return is_string($domain) && $domain !== '' ? $domain : null;
        } catch (\Throwable) {
            // A tenancy package mid-migration, or a tenant without domains configured. The
            // caller falls back to the configured base domain.
            return null;
        }
    }

    /** The accept path with the token substituted, relative and without a leading slash. */
    private function acceptPath(string $token): string
    {
        $prefix = trim($this->settings->string('routes.prefix', 'impersonator'), '/');
        $path = $this->settings->string('routes.accept_path', 'accept/{token}');

        // The token is placed by substitution rather than concatenation so an application
        // can put it mid-path — `accept/{token}/confirm` — without this needing to know.
        $path = str_contains($path, '{token}')
            ? str_replace('{token}', rawurlencode($token), $path)
            : trim($path, '/') . '/' . rawurlencode($token);

        return trim($prefix . '/' . trim($path, '/'), '/');
    }

    private function assemble(string $host, string $path): string
    {
        $scheme = $this->settings->enum('urls.scheme', ['https', 'http'], 'https');
        $port = $this->settings->positiveIntOrNull('urls.port');

        // A port is only appended when it is not the scheme's default: `https://host:443`
        // is legal but differs textually from what the app's own links look like, and an
        // exact-match host allowlist elsewhere would then disagree with it.
        $authority = $host;

        if ($port !== null && ($scheme !== 'https' || $port !== 443) && ($scheme !== 'http' || $port !== 80)) {
            $authority .= ':' . $port;
        }

        return $scheme . '://' . $authority . '/' . $path;
    }

    private function currentHost(): ?string
    {
        $url = config('app.url');

        if (! is_string($url) || $url === '') {
            return null;
        }

        $host = parse_url($url, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : null;
    }
}
