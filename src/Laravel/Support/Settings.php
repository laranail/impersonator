<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Illuminate\Contracts\Config\Repository as Config;

/**
 * Typed reads of the package's own config, with the `impersonator.` prefix applied.
 *
 * Config is `mixed` at the boundary, and the alternative to this is a cast at every
 * call site — which is how `(int) ['array']` silently becomes `1`, or a mistyped
 * `banner.theme` reaches a template as `Array`. Each accessor here returns the
 * requested type or the documented default, never a coerced surprise.
 *
 * Note these are deliberately **lenient**: a malformed cosmetic setting degrades to
 * its default rather than failing a request. Security-critical names — guards,
 * drivers, modes — are read strictly instead, and throw, because silently
 * substituting a default guard would authenticate against the wrong provider.
 */
final readonly class Settings
{
    public function __construct(private Config $config) {}

    public function raw(string $key, mixed $default = null): mixed
    {
        return $this->config->get('laranail.impersonator.' . $key, $default);
    }

    public function string(string $key, string $default): string
    {
        $value = $this->raw($key);

        return is_string($value) && $value !== '' ? $value : $default;
    }

    public function nullableString(string $key): ?string
    {
        $value = $this->raw($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /** One of `$allowed`, or the default — for enumerated settings like a theme. */
    public function enum(string $key, array $allowed, string $default): string
    {
        $value = $this->raw($key);

        return is_string($value) && in_array($value, $allowed, true) ? $value : $default;
    }

    public function int(string $key, int $default): int
    {
        $value = $this->raw($key);

        // is_numeric rather than is_int: an env var arrives as a string, so
        // IMPERSONATOR_MAX_DURATION=60 is "60" and must still mean 60.
        return is_numeric($value) ? (int) $value : $default;
    }

    /**
     * A positive int, or null. Used for the limits where null means "unlimited" —
     * `max_duration`, `retention_days`, `max_active_per_impersonator`.
     */
    public function positiveIntOrNull(string $key): ?int
    {
        $value = $this->raw($key);

        if (! is_numeric($value)) {
            return null;
        }

        return (int) $value > 0 ? (int) $value : null;
    }

    public function bool(string $key, bool $default): bool
    {
        $value = $this->raw($key);

        if (is_bool($value)) {
            return $value;
        }

        // Env vars again: "false" and "0" are strings and must not read as true.
        return match (true) {
            $value === 1, $value === '1', $value === 'true' => true,
            $value === 0, $value === '0', $value === 'false' => false,
            default => $default,
        };
    }

    public function float(string $key, float $default): float
    {
        $value = $this->raw($key);

        return is_numeric($value) ? (float) $value : $default;
    }

    /** @return array<array-key, mixed> */
    public function array(string $key): array
    {
        $value = $this->raw($key, []);

        return is_array($value) ? $value : [];
    }

    /**
     * The non-empty strings in a config array, discarding anything else.
     *
     * @return list<string>
     */
    public function stringList(string $key): array
    {
        $list = [];

        foreach ($this->array($key) as $value) {
            if (is_string($value) && trim($value) !== '') {
                $list[] = $value;
            }
        }

        return $list;
    }

    /**
     * A config array narrowed to string keys, for the metadata and context arrays
     * that cross into Core value objects typed `array<string, mixed>`.
     *
     * @param array<array-key, mixed> $data
     * @return array<string, mixed>
     */
    public static function stringKeyed(array $data): array
    {
        $narrowed = [];

        foreach ($data as $key => $value) {
            $narrowed[(string) $key] = $value;
        }

        return $narrowed;
    }
}
