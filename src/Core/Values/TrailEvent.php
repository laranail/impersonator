<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use DateTimeImmutable;

/**
 * One action taken while impersonating — a single request, recorded against its
 * parent audit row.
 *
 * This is the difference between knowing an admin was in an account and knowing
 * what they did there, which is the question every compliance review actually
 * asks.
 *
 * `payload` is null unless `trail.record_payloads` is on, and when present it
 * has already passed through redaction before reaching this object. The Core
 * layer never redacts on write: a value object that could hold either a raw or
 * a scrubbed payload depending on the caller is exactly the ambiguity that
 * leaks a password into a database.
 */
final readonly class TrailEvent
{
    /** @param array<string, mixed>|null $payload */
    public function __construct(
        public string $auditId,
        public string $method,
        public string $path,
        public ?string $routeName = null,
        public ?int $status = null,
        public ?float $durationMs = null,
        public ?array $payload = null,
        public ?DateTimeImmutable $occurredAt = null,
    ) {}

    /** True for the HTTP verbs that can change state. */
    public function isWrite(): bool
    {
        return in_array(strtoupper($this->method), ['POST', 'PUT', 'PATCH', 'DELETE'], true);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'audit_id'    => $this->auditId,
            'method'      => strtoupper($this->method),
            'path'        => $this->path,
            'route_name'  => $this->routeName,
            'status'      => $this->status,
            'duration_ms' => $this->durationMs,
            'payload'     => $this->payload,
            'occurred_at' => $this->occurredAt?->format(DATE_ATOM),
        ];
    }
}
