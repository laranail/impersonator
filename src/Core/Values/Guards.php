<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

/**
 * The guard on each side of an impersonation.
 *
 * These are frequently not the same guard: an operator authenticated on an
 * `admin` guard enters, and the target is logged in on `web`. Collapsing them
 * into one value is what makes "leave" ambiguous — you cannot tell which guard
 * to restore — so the pair travels together everywhere.
 */
final readonly class Guards
{
    public function __construct(
        public string $impersonator,
        public string $target,
    ) {}

    public static function of(string $impersonator, ?string $target = null): self
    {
        return new self($impersonator, $target ?? $impersonator);
    }

    public static function both(string $guard): self
    {
        return new self($guard, $guard);
    }

    public function areSame(): bool
    {
        return $this->impersonator === $this->target;
    }

    /** @return array{impersonator: string, target: string} */
    public function toArray(): array
    {
        return [
            'impersonator' => $this->impersonator,
            'target' => $this->target,
        ];
    }
}
