<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Middleware;

use Closure;
use DateTimeImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Simtabi\Laranail\Impersonator\Core\Contracts\TrailStore;
use Simtabi\Laranail\Impersonator\Core\Support\Redactor;
use Simtabi\Laranail\Impersonator\Core\Values\TrailEvent;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Symfony\Component\HttpFoundation\Response;

/**
 * Records one trail row per impersonated request.
 *
 * Written in `terminate` so the response status and the real duration are known, and
 * so the write never sits between the user and their page.
 *
 * Payloads are off by default: a request body is the likeliest place for personal
 * data to end up permanently recorded. When they are on, redaction happens here —
 * before the value object is built — because a value object that could hold either a
 * raw or a scrubbed payload depending on its caller is exactly the ambiguity that
 * leaks a password into a database.
 */
final readonly class RecordImpersonationTrail
{
    public function __construct(
        private ImpersonationManager $impersonator,
        private TrailStore $trail,
        private Settings $settings,
    ) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        // Stashed on the request so `terminate` can measure the real duration; the
        // container binding is not per-request-immutable enough to hold it.
        $request->attributes->set('impersonator_started_at', microtime(true));

        return $next($request);
    }

    public function terminate(Request $request, Response $response): void
    {
        if (! $this->settings->bool('trail.enabled', true)) {
            return;
        }

        $session = $this->impersonator->current();

        if ($session === null || $this->isIgnored($request)) {
            return;
        }

        if (! $this->shouldSample()) {
            return;
        }

        $startedAt = $request->attributes->get('impersonator_started_at');

        $this->trail->record(new TrailEvent(
            auditId: $session->auditId,
            method: $request->getMethod(),
            path: '/' . ltrim($request->path(), '/'),
            routeName: $request->route() === null ? null : $request->route()->getName(),
            status: $response->getStatusCode(),
            durationMs: is_float($startedAt) ? round((microtime(true) - $startedAt) * 1000, 2) : null,
            payload: $this->payload($request),
            occurredAt: new DateTimeImmutable,
        ));
    }

    /**
     * Sampling is per request, never per session, so a sampled trail still spans the
     * whole impersonation instead of recording only its opening minutes.
     */
    private function shouldSample(): bool
    {
        $rate = $this->settings->float('trail.sample_rate', 1.0);

        if ($rate >= 1.0) {
            return true;
        }

        if ($rate <= 0.0) {
            return false;
        }

        return (random_int(1, 1_000_000) / 1_000_000) <= $rate;
    }

    private function isIgnored(Request $request): bool
    {
        $path = ltrim($request->path(), '/');

        foreach ($this->settings->stringList('trail.ignore_paths') as $pattern) {
            if (Str::is(ltrim($pattern, '/'), $path)) {
                return true;
            }
        }

        return false;
    }

    /** @return array<string, mixed>|null */
    private function payload(Request $request): ?array
    {
        if (! $this->settings->bool('trail.record_payloads', false)) {
            return null;
        }

        $input = $request->except(['_token', '_method']);

        if ($input === []) {
            return null;
        }

        return Redactor::for($this->settings->stringList('trail.redact'))->scrub($input);
    }
}
