<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use Simtabi\Laranail\Impersonator\Core\Exceptions\InvalidIdentity;

/**
 * A fully-resolved intent to impersonate, assembled by the bridge before any
 * authorization runs.
 *
 * Everything a policy, driver or adapter needs is already on this object, which
 * is what lets the whole authorization stack be pure and unit-testable without
 * a request, a container or a database. Note there is no mutable state: a
 * different mode means a different request, which is the type-level expression
 * of "the only path to another mode is leave and re-enter".
 */
final readonly class ImpersonationRequest
{
    /** @param array<string, mixed> $metadata */
    public function __construct(
        public Identity $impersonator,
        public Identity $target,
        public Mode $mode,
        public Guards $guards,
        public string $driver,
        public string $adapter,
        public ?string $reason = null,
        public ?string $redirectTo = null,
        public ?string $tenantId = null,
        public ?string $ip = null,
        public ?string $userAgent = null,
        public array $metadata = [],
    ) {}

    /**
     * Rebuild from the array form.
     *
     * Used when a handoff token is redeemed: the request was serialised at issue time and
     * has to come back intact, because the redemption re-runs the whole authorization
     * stack against it rather than trusting the decision made when the token was minted.
     *
     * @param  array<string, mixed>  $data
     *
     * @throws InvalidIdentity when the
     *                         stored identities are unreadable, which means the token cannot be trusted
     */
    public static function fromArray(array $data): self
    {
        $str = static fn (string $key, string $default = ''): string => is_string($data[$key] ?? null)
            && $data[$key] !== ''
                ? $data[$key]
                : $default;

        $nullable = static fn (string $key): ?string => is_string($data[$key] ?? null)
            && $data[$key] !== ''
                ? $data[$key]
                : null;

        $identity = static function (string $key) use ($data): Identity {
            $raw = $data[$key] ?? null;

            if (! is_array($raw) || ! isset($raw['type'], $raw['id'])
                || ! is_string($raw['type'])
                || (! is_int($raw['id']) && ! is_string($raw['id']))) {
                throw InvalidIdentity::emptyType();
            }

            return new Identity($raw['type'], $raw['id'], is_string($raw['label'] ?? null) ? $raw['label'] : null);
        };

        $guards = is_array($data['guards'] ?? null) ? $data['guards'] : [];
        $metadata = $data['metadata'] ?? null;

        return new self(
            impersonator: $identity('impersonator'),
            target: $identity('target'),
            mode: Mode::of($str('mode', Mode::FULL)),
            guards: new Guards(
                is_string($guards['impersonator'] ?? null) ? $guards['impersonator'] : 'web',
                is_string($guards['target'] ?? null) ? $guards['target'] : 'web',
            ),
            driver: $str('driver', 'token'),
            adapter: $str('adapter', 'session'),
            reason: $nullable('reason'),
            redirectTo: $nullable('redirect_to'),
            tenantId: $nullable('tenant_id'),
            ip: $nullable('ip'),
            userAgent: $nullable('user_agent'),
            metadata: is_array($metadata) ? self::stringKeys($metadata) : [],
        );
    }

    public function isSelfImpersonation(): bool
    {
        return $this->impersonator->is($this->target);
    }

    public function hasReason(): bool
    {
        return $this->reason !== null && trim($this->reason) !== '';
    }

    public function withMode(Mode $mode): self
    {
        return new self(
            $this->impersonator,
            $this->target,
            $mode,
            $this->guards,
            $this->driver,
            $this->adapter,
            $this->reason,
            $this->redirectTo,
            $this->tenantId,
            $this->ip,
            $this->userAgent,
            $this->metadata,
        );
    }

    /** @param array<string, mixed> $metadata */
    public function withMetadata(array $metadata): self
    {
        return new self(
            $this->impersonator,
            $this->target,
            $this->mode,
            $this->guards,
            $this->driver,
            $this->adapter,
            $this->reason,
            $this->redirectTo,
            $this->tenantId,
            $this->ip,
            $this->userAgent,
            [...$this->metadata, ...$metadata],
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'impersonator' => $this->impersonator->toArray(),
            'target' => $this->target->toArray(),
            'mode' => $this->mode->name,
            'guards' => $this->guards->toArray(),
            'driver' => $this->driver,
            'adapter' => $this->adapter,
            'reason' => $this->reason,
            'redirect_to' => $this->redirectTo,
            'tenant_id' => $this->tenantId,
            'ip' => $this->ip,
            'user_agent' => $this->userAgent,
            'metadata' => $this->metadata,
        ];
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @return array<string, mixed>
     */
    private static function stringKeys(array $data): array
    {
        $narrowed = [];

        foreach ($data as $key => $value) {
            $narrowed[(string) $key] = $value;
        }

        return $narrowed;
    }
}
