<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Support;

/**
 * Removes sensitive values from a payload before it is recorded.
 *
 * Pure, and deliberately in Core: this is the last thing standing between a request
 * body and a permanent database row, so it has to be unit-testable without a
 * framework, a request or a database.
 *
 * Three properties are what make it actually work:
 *
 *  - **Recursive.** A password nested three levels down inside a JSON body is still a
 *    password. Flat key checking is the usual reason redaction misses.
 *  - **Substring, case-insensitive.** `password_confirmation`, `PasswordConfirm` and
 *    `current-password` all match `password`, so the configured list does not have to
 *    enumerate every spelling an application might use.
 *  - **Keys are replaced, never removed.** The reader needs to know a field was
 *    present and withheld; a silently absent key reads as a field that was never
 *    sent, which changes what the trail appears to say.
 *
 * It is a filter, not a guarantee — which is why payload recording is off by default.
 */
final readonly class Redactor
{
    public const string PLACEHOLDER = '[redacted]';

    /** @param list<string> $sensitiveKeys lowercased substrings to match */
    private function __construct(private array $sensitiveKeys) {}

    /** @param list<string> $sensitiveKeys */
    public static function for(array $sensitiveKeys): self
    {
        $normalised = [];

        foreach ($sensitiveKeys as $key) {
            $trimmed = trim(strtolower($key));

            if ($trimmed !== '') {
                $normalised[] = $trimmed;
            }
        }

        return new self($normalised);
    }

    /**
     * @param array<array-key, mixed> $payload
     * @return array<string, mixed>
     */
    public function scrub(array $payload, int $depth = 0): array
    {
        // A bound on recursion: a deeply nested or self-referential structure must
        // not turn redaction into a stack overflow on the request it is protecting.
        if ($depth > 16) {
            return ['_truncated' => self::PLACEHOLDER];
        }

        $scrubbed = [];

        foreach ($payload as $key => $value) {
            $name = (string) $key;

            if ($this->isSensitive($name)) {
                // Replaced whether it is a scalar or a whole subtree: a sensitive key
                // holding an array is still a sensitive key.
                $scrubbed[$name] = self::PLACEHOLDER;

                continue;
            }

            $scrubbed[$name] = is_array($value) ? $this->scrub($value, $depth + 1) : $this->scalar($value);
        }

        return $scrubbed;
    }

    public function isSensitive(string $key): bool
    {
        $needle = strtolower($key);

        return array_any($this->sensitiveKeys, fn (string $sensitive): bool => str_contains($needle, $sensitive));
    }

    /**
     * Objects and resources are reduced to a type label rather than serialised: an
     * uploaded file or a model instance in a payload would otherwise pull its entire
     * graph into the trail.
     */
    private function scalar(mixed $value): mixed
    {
        return match (true) {
            $value === null, is_scalar($value) => $value,
            is_object($value) => '[object ' . $value::class . ']',
            default => '[' . get_debug_type($value) . ']',
        };
    }
}
