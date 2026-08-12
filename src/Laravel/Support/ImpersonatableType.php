<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Illuminate\Database\Eloquent\Model;

/**
 * One kind of account that may be impersonated.
 *
 * A package aimed at real applications cannot assume a single `User` model. A
 * marketplace has customers and vendors; a B2B product has staff, tenant admins and end
 * users; anything with a separate admin panel has at least two. Those models routinely
 * live on *different guards*, which is the part a single global `guards.target` setting
 * cannot express — and getting it wrong means authenticating a vendor against the
 * customer provider.
 *
 * So a type carries everything that varies per model:
 *
 *  - `alias` — the morph key written into the audit row. Stable across class renames,
 *    which is what keeps a five-year-old audit row resolvable.
 *  - `guard` — the guard this kind of account authenticates on. Null falls back to the
 *    global `guards.target`.
 *  - `displayName` — the attribute to label them by, since `name` is not universal:
 *    a vendor may be `company_name`, a customer `full_name`.
 *  - `label` — a human name for the *type* itself, for a UI that offers a choice.
 */
final readonly class ImpersonatableType
{
    /** @param class-string<Model> $model */
    public function __construct(
        public string $alias,
        public string $model,
        public ?string $guard = null,
        public ?string $displayName = null,
        public ?string $label = null,
    ) {}

    /**
     * Build from a config entry, which may be either shape.
     *
     * A bare class string is the common case and stays a one-liner; the descriptive array
     * form is there for the models that need more. Supporting both means adding a second
     * model never forces rewriting the first entry.
     *
     * Returns null for anything that is not an installed Eloquent model, so a typo or a
     * stale entry narrows the registry instead of becoming a crash on an unrelated
     * request.
     */
    public static function fromConfig(int|string $key, mixed $entry): ?self
    {
        if (is_string($entry)) {
            return self::make(is_string($key) ? $key : $entry, $entry);
        }

        if (! is_array($entry)) {
            return null;
        }

        $model = $entry['model'] ?? (is_string($key) ? null : null);

        if (! is_string($model)) {
            return null;
        }

        return self::make(
            alias: is_string($key) ? $key : $model,
            model: $model,
            guard: self::string($entry['guard'] ?? null),
            displayName: self::string($entry['display_name'] ?? null),
            label: self::string($entry['label'] ?? null),
        );
    }

    public static function make(
        string $alias,
        string $model,
        ?string $guard = null,
        ?string $displayName = null,
        ?string $label = null,
    ): ?self {
        if (! is_subclass_of($model, Model::class)) {
            return null;
        }

        return new self($alias, $model, $guard, $displayName, $label);
    }

    /** The guard this type authenticates on, given the global fallback. */
    public function guardOr(string $fallback): string
    {
        return $this->guard ?? $fallback;
    }

    /** A human name for the type, derived from the alias when none was given. */
    public function label(): string
    {
        return $this->label ?? ucfirst(str_replace(['_', '-'], ' ', $this->alias));
    }

    private static function string(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? $value : null;
    }
}
