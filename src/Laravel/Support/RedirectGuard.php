<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Illuminate\Contracts\Config\Repository as Config;

/**
 * Validates every redirect target the package emits.
 *
 * Three separate targets are attacker-influenceable — a caller-supplied
 * `redirectTo`, the post-accept redirect, and the leave redirect — and all three
 * pass through here. An open redirect on an impersonation endpoint is worse than
 * the usual case: the link is one a support engineer has been trained to click,
 * arrives from a trusted domain, and lands on a login page, which is precisely
 * the shape of a credential-phishing primitive.
 *
 * Relative paths only, by default. Absolute URLs require both `allow_absolute`
 * and an exact host match in `allowed_hosts` — no wildcards and no suffix
 * matching, because `allowed_hosts = ['example.com']` matching
 * `evil-example.com` or `example.com.attacker.tld` is how a host allowlist
 * usually fails.
 */
final readonly class RedirectGuard
{
    public function __construct(private Config $config) {}

    public function afterEnter(?string $requested = null): string
    {
        return $this->safe($requested, $this->configured('after_enter'));
    }

    public function afterLeave(?string $requested = null): string
    {
        return $this->safe($requested, $this->configured('after_leave'));
    }

    /**
     * The requested target if it passes, the fallback otherwise.
     *
     * Never throws. A rejected redirect is not worth failing a request over — the
     * operator still needs to land somewhere, and the safe destination is a
     * strictly better outcome than an error page.
     */
    public function safe(?string $requested, string $fallback): string
    {
        if ($requested === null || trim($requested) === '') {
            return $fallback;
        }

        return $this->isSafe($requested) ? $requested : $fallback;
    }

    public function isSafe(string $target): bool
    {
        $target = trim($target);

        if ($target === '') {
            return false;
        }

        // Control characters and whitespace inside a URL are header-splitting and
        // parser-confusion material; nothing legitimate needs them.
        if (preg_match('/[\x00-\x20\x7f]/', $target) === 1) {
            return false;
        }

        return str_starts_with($target, '/')
            ? $this->isSafeRelativePath($target)
            : $this->isAllowedAbsoluteUrl($target);
    }

    /**
     * A path is safe only when it is genuinely path-relative to this host.
     *
     * `//evil.com` is protocol-relative and leaves the site despite starting with
     * a slash, and browsers normalise a backslash to a forward slash — so `/\evil.com`
     * leaves too. Both start with `/`, which is why a naive `str_starts_with('/')`
     * check is not enough on its own.
     */
    private function isSafeRelativePath(string $path): bool
    {
        $normalised = str_replace('\\', '/', $path);

        return ! str_starts_with($normalised, '//');
    }

    private function isAllowedAbsoluteUrl(string $url): bool
    {
        if (! $this->config->get('impersonator.redirects.allow_absolute', false)) {
            return false;
        }

        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            return false;
        }

        if (! in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            return false;
        }

        // Credentials in a redirect target are how `https://trusted.com@evil.com`
        // gets past a reader skimming the start of a URL.
        if (isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }

        return in_array(strtolower($parts['host']), $this->allowedHosts(), true);
    }

    /** @return list<string> lowercased, for case-insensitive exact matching */
    private function allowedHosts(): array
    {
        $hosts = $this->config->get('impersonator.redirects.allowed_hosts', []);

        if (! is_array($hosts)) {
            return [];
        }

        $normalised = [];

        foreach ($hosts as $host) {
            if (is_string($host) && trim($host) !== '') {
                $normalised[] = strtolower(trim($host));
            }
        }

        return $normalised;
    }

    private function configured(string $key): string
    {
        $value = $this->config->get('impersonator.redirects.' . $key, '/');

        // The fallback itself is config, so it is validated too — otherwise a
        // misconfigured default would be the one target that bypassed the check.
        return is_string($value) && $value !== '' && $this->isSafe($value) ? $value : '/';
    }
}
