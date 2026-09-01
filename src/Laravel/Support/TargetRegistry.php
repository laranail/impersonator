<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;

/**
 * The set of account types this installation may impersonate.
 *
 * Two sources, merged: the `targets.allowlist` config, and runtime registrations made
 * through `Impersonator::registerTarget()`. The runtime path exists so a package can ship
 * its own impersonatable type — a vendor module registering `vendor` from its own service
 * provider — without asking the host application to edit config it does not own.
 *
 * Runtime registrations win over config of the same alias, which is the useful precedence:
 * a host application can always override what a package registered, and the direction of
 * that override is the one people expect.
 *
 * This is also the security boundary. An empty registry denies every target rather than
 * permitting any, because the list is what stops an attacker-supplied class name becoming
 * a loaded model.
 */
final class TargetRegistry
{
    /** @var array<string, ImpersonatableType> */
    private array $registered = [];

    /** @var array<string, ImpersonatableType>|null memoised per request */
    private ?array $resolved = null;

    public function __construct(private readonly Settings $settings) {}

    /**
     * Register a type at runtime, from a service provider.
     *
     * Silently ignores a class that is not an installed Eloquent model: a provider booting
     * against a model that has since been removed should not take the application down.
     */
    public function register(
        string $alias,
        string $model,
        ?string $guard = null,
        ?string $displayName = null,
        ?string $label = null,
    ): self {
        $type = ImpersonatableType::make($alias, $model, $guard, $displayName, $label);

        if ($type !== null) {
            $this->registered[$alias] = $type;
            $this->resolved = null;
        }

        return $this;
    }

    public function add(ImpersonatableType $type): self
    {
        $this->registered[$type->alias] = $type;
        $this->resolved = null;

        return $this;
    }

    /** @return array<string, ImpersonatableType> alias => type */
    public function all(): array
    {
        if ($this->resolved !== null) {
            return $this->resolved;
        }

        $types = [];

        foreach ($this->settings->array('targets.allowlist') as $key => $entry) {
            $type = ImpersonatableType::fromConfig($key, $entry);

            if ($type !== null) {
                $types[$type->alias] = $type;
            }
        }

        // Runtime last, so it overrides config of the same alias.
        $resolved = [...$types, ...$this->registered];

        $this->publishMorphAliases($resolved);

        return $this->resolved = $resolved;
    }

    /**
     * Find a type by its alias, its class name, or a globally registered morph alias.
     *
     * Three lookups because callers legitimately hold different forms: request input
     * carries the alias, a Blade component holds a model instance, and an old audit row
     * may carry a fully-qualified class name from before an alias was introduced.
     */
    public function find(string $aliasOrClass): ?ImpersonatableType
    {
        $types = $this->all();

        if (isset($types[$aliasOrClass])) {
            return $types[$aliasOrClass];
        }

        foreach ($types as $type) {
            if ($type->model === $aliasOrClass) {
                return $type;
            }
        }

        // A morph alias the application enforced globally, pointing at a class that *is*
        // registered here under a different key.
        $mapped = Relation::morphMap()[$aliasOrClass] ?? null;

        if (is_string($mapped)) {
            foreach ($types as $type) {
                if ($type->model === $mapped) {
                    return $type;
                }
            }
        }

        return null;
    }

    public function forModel(Model $model): ?ImpersonatableType
    {
        return $this->find($model->getMorphClass()) ?? $this->find($model::class);
    }

    public function has(string $aliasOrClass): bool
    {
        return $this->find($aliasOrClass) !== null;
    }

    /** @return list<string> the aliases, for validation rules and UIs */
    public function aliases(): array
    {
        return array_keys($this->all());
    }

    /** @return array<string, class-string<Model>> alias => class, the legacy shape */
    public function map(): array
    {
        return array_map(
            static fn (ImpersonatableType $type): string => $type->model,
            $this->all(),
        );
    }

    /**
     * Alias => human label, for a UI offering a choice of account type.
     *
     * @return array<string, string>
     */
    public function labels(): array
    {
        return array_map(
            static fn (ImpersonatableType $type): string => $type->label(),
            $this->all(),
        );
    }

    /** Clears the memoised config read. Used by tests that change config mid-run. */
    public function flush(): self
    {
        $this->resolved = null;

        return $this;
    }

    /**
     * Teach Eloquent the aliases this registry knows, at the moment it learns them.
     *
     * Here rather than in the service provider, and the reason is a bug that shape produced:
     * calling this registry during boot **memoises it against boot-time config**, so a later
     * `registerTarget()` — or any config change — was silently ignored for the rest of the request.
     * Publishing from inside the resolution instead means the map is populated exactly when the
     * allowlist is first needed and re-populated whenever `flush()` or `add()` invalidates it.
     *
     * Eloquent needs this because the package's own `morphTo()` relations read a `*_type` column
     * holding an alias. With no entry for `user`, Eloquent instantiates a class literally named
     * `user` — *"Class \"user\" not found"*. Everything else here resolves aliases through this
     * registry, which is why nothing but a relation depends on Laravel's map.
     *
     * **An alias already in the map is never overwritten.** Repointing one changes which class every
     * historic row resolves to, application-wide and not merely in this package's tables.
     *
     * @param  array<string, ImpersonatableType>  $types
     */
    private function publishMorphAliases(array $types): void
    {
        if (! $this->settings->bool('morphs.register_map', true)) {
            return;
        }

        $aliases = [];

        foreach ($types as $type) {
            // An entry whose "alias" is its own class name has no alias — that is what the
            // allowlist's shorthand form produces. Publishing `Foo::class => Foo::class` buys
            // nothing (Eloquent resolves a class name natively) and actively harms: additions are
            // prepended to the morph map, so a pseudo-alias would be found *before* a real one the
            // application had registered, and `aliasFor()` would start writing class names into
            // rows that should carry the alias.
            if ($type->alias !== $type->model) {
                $aliases[$type->alias] = $type->model;
            }
        }

        $additions = array_diff_key($aliases, Relation::morphMap());

        if ($additions !== []) {
            Relation::morphMap($additions);
        }
    }
}
