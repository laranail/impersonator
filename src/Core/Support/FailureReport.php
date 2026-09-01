<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Support;

use Throwable;

/**
 * The observable record of degraded state.
 *
 * A report that was paged once is not a queryable state, so anything that
 * continued in a reduced condition is recorded here — which is what lets a health
 * probe, a status page, the doctor command and CI all see the same fact.
 *
 * The CI gate is the important consumer: asserting this is healthy after a normal
 * boot catches a broken degradable operation that would otherwise pass silently,
 * without relying on a dev-only crash that production would never reproduce.
 */
final class FailureReport
{
    /** @var array<string, array{message: string, type: string}> */
    private array $degraded = [];

    public function recordDegraded(string $operation, Throwable $cause): void
    {
        // First failure wins: a later, shallower error must not overwrite the
        // original cause of a capability that has been down since boot.
        $this->degraded[$operation] ??= [
            'message' => $cause->getMessage(),
            'type' => $cause::class,
        ];
    }

    public function isHealthy(): bool
    {
        return $this->degraded === [];
    }

    /** @return array<string, array{message: string, type: string}> */
    public function degraded(): array
    {
        return $this->degraded;
    }

    /** @return list<string> the operation names currently degraded */
    public function degradedOperations(): array
    {
        return array_keys($this->degraded);
    }

    public function isDegraded(string $operation): bool
    {
        return isset($this->degraded[$operation]);
    }

    public function flush(): void
    {
        $this->degraded = [];
    }
}
