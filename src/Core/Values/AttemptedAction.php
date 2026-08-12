<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

/**
 * A framework-agnostic description of something the impersonated session is
 * trying to do, handed to a ModeEnforcer for judgement.
 *
 * The Core layer cannot see an Illuminate request, and that constraint turns out
 * to be a feature: because a mode judges this flat value object instead of a
 * request, the same enforcer covers an HTTP route, a queued job, a console
 * command, and a direct Eloquent write, and every one of those is unit-testable
 * without booting a framework.
 */
final readonly class AttemptedAction
{
    /**
     * @param list<string> $abilities gate abilities this action would exercise
     * @param array<string, mixed> $context
     */
    public function __construct(
        public string $method,
        public string $path,
        public ?string $routeName = null,
        public array $abilities = [],
        public ?string $modelClass = null,
        public array $context = [],
    ) {}

    /** An HTTP request. */
    public static function http(string $method, string $path, ?string $routeName = null): self
    {
        return new self(method: $method, path: $path, routeName: $routeName);
    }

    /**
     * A persistence write, for the stricter `read_only.prevent_writes` net that
     * catches writes hidden behind a GET route.
     */
    public static function write(string $modelClass, string $operation = 'save', ?string $path = null): self
    {
        return new self(
            method: strtoupper($operation),
            path: $path ?? '',
            modelClass: $modelClass,
            context: ['operation' => $operation],
        );
    }

    /** A gate ability check. */
    public static function ability(string $ability, ?string $modelClass = null): self
    {
        return new self(
            method: 'ABILITY',
            path: '',
            abilities: [$ability],
            modelClass: $modelClass,
        );
    }

    /**
     * The same action with extra context merged in.
     *
     * Immutable, like everything else here. Used by the bridge to attach what the HTTP envelope cannot
     * say on its own — a Livewire request's component and method, which are in the payload rather than
     * in the route.
     *
     * @param array<string, mixed> $context
     */
    public function withContext(array $context): self
    {
        return new self(
            $this->method,
            $this->path,
            $this->routeName,
            $this->abilities,
            $this->modelClass,
            [...$this->context, ...$context],
        );
    }

    /**
     * Identifiers a Livewire request is invoking, or an empty list.
     *
     * Read from context rather than being a constructor field, because Core has no notion of Livewire
     * and should not gain one — this is a bridge concern travelling in the bag Core already provides.
     *
     * @return list<string>
     */
    public function livewireIdentifiers(): array
    {
        $identifiers = $this->context['livewire'] ?? null;

        if (! is_array($identifiers)) {
            return [];
        }

        return array_values(array_filter($identifiers, is_string(...)));
    }

    public function isUnsafeMethod(): bool
    {
        return in_array($this->normalizedMethod(), ['POST', 'PUT', 'PATCH', 'DELETE'], true);
    }

    public function normalizedMethod(): string
    {
        return strtoupper($this->method);
    }

    public function hasAbility(string $ability): bool
    {
        return in_array($ability, $this->abilities, true);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'method' => $this->normalizedMethod(),
            'path' => $this->path,
            'route_name' => $this->routeName,
            'abilities' => $this->abilities,
            'model_class' => $this->modelClass,
            'context' => $this->context,
        ];
    }
}
