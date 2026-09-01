<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Illuminate\Http\Request;

/**
 * What a Livewire request is actually trying to do.
 *
 * Every Livewire action POSTs to **one** endpoint with the component and the method in the payload, so
 * from the outside they are indistinguishable: one route name, one path, one HTTP method for every
 * action in the application. That makes `deny_routes`, `deny_paths` and `allowed_methods` inert under
 * Livewire — a rule naming `password.update` matches nothing, and a rule broad enough to match blocks
 * the whole application.
 *
 * The consequence was that `limited` mode was substantially weaker under Livewire than it looked, with
 * only `deny_models` and `deny_abilities` still biting. This class closes that by reading what the
 * payload says, so a deny rule can name `ProfileForm::updatePassword` and mean it.
 *
 * ### Written against the payload shape, not against Livewire
 *
 * Livewire is not a dependency here and never should be — this package works the same with or without
 * it. So there is no type-hint on a Livewire class anywhere, and this reads the request as plain data.
 * Both major shapes are handled because both are in the wild:
 *
 *  - **Livewire 3**: `POST livewire/update` with `components[].snapshot` (a JSON *string* whose
 *    `memo.name` is the component) and `components[].calls[].method`.
 *  - **Livewire 2**: `POST livewire/message/{component}` with `updates[]` entries of type
 *    `callMethod` and `payload.method`.
 *
 * Anything it cannot parse yields an empty list, which means the Livewire axis simply does not match —
 * never that the request is allowed. The other axes still apply, and `read_only` is unaffected either
 * way because its guard sits at the persistence layer and does not care how the request arrived.
 */
final readonly class LivewireAction
{
    /**
     * The `Component::method` identifiers this request is invoking.
     *
     * Returns the qualified form plus the bare component and bare method, so a rule can be written at
     * whichever granularity fits: `ProfileForm::updatePassword`, `ProfileForm::*`, or `*::destroy`.
     *
     * @return list<string>
     */
    public static function identifiersFrom(Request $request): array
    {
        if (! self::looksLikeLivewire($request)) {
            return [];
        }

        $identifiers = [];

        foreach (self::componentsFrom($request) as [$component, $methods]) {
            if ($component !== null) {
                $identifiers[] = $component;
            }

            foreach ($methods as $method) {
                $identifiers[] = $method;

                if ($component !== null) {
                    $identifiers[] = $component.'::'.$method;
                }
            }
        }

        return array_values(array_unique($identifiers));
    }

    /**
     * A cheap path test before any payload parsing.
     *
     * Checked first because this runs on every impersonated request: decoding a JSON body to discover
     * it was not Livewire would be a cost paid by every application, including the ones not using it.
     */
    public static function looksLikeLivewire(Request $request): bool
    {
        $path = trim($request->path(), '/');

        return $path === 'livewire/update'
            || str_starts_with($path, 'livewire/message')
            || $request->hasHeader('X-Livewire');
    }

    /**
     * @return list<array{0: string|null, 1: list<string>}> component name, methods called
     */
    private static function componentsFrom(Request $request): array
    {
        $components = $request->input('components');

        if (is_array($components)) {
            return self::fromV3($components);
        }

        return self::fromV2($request);
    }

    /**
     * Livewire 3: the component name lives inside a JSON-encoded `snapshot` string.
     *
     * `memo.name` rather than the class: Livewire resolves a registered alias, and that alias is what
     * an application author would write in a config file. Falls back to the class when only that is
     * present, so a rule can name either.
     *
     * @param  array<array-key, mixed>  $components
     * @return list<array{0: string|null, 1: list<string>}>
     */
    private static function fromV3(array $components): array
    {
        $found = [];

        foreach ($components as $component) {
            if (! is_array($component)) {
                continue;
            }

            $name = null;
            $snapshot = $component['snapshot'] ?? null;

            // A *string* of JSON, not an array — decoding it is the only way to the component name.
            if (is_string($snapshot) && $snapshot !== '') {
                $decoded = json_decode($snapshot, true);

                if (is_array($decoded) && is_array($decoded['memo'] ?? null)) {
                    $memo = $decoded['memo'];
                    $candidate = $memo['name'] ?? $memo['class'] ?? null;
                    $name = is_string($candidate) && $candidate !== '' ? $candidate : null;
                }
            }

            $methods = [];

            foreach (is_array($component['calls'] ?? null) ? $component['calls'] : [] as $call) {
                if (is_array($call) && is_string($call['method'] ?? null) && $call['method'] !== '') {
                    $methods[] = $call['method'];
                }
            }

            $found[] = [$name, $methods];
        }

        return $found;
    }

    /**
     * Livewire 2: the component is the last path segment, the methods are `callMethod` updates.
     *
     * @return list<array{0: string|null, 1: list<string>}>
     */
    private static function fromV2(Request $request): array
    {
        $path = trim($request->path(), '/');
        $name = null;

        if (str_starts_with($path, 'livewire/message/')) {
            $candidate = substr($path, strlen('livewire/message/'));
            $name = $candidate === '' ? null : $candidate;
        }

        $methods = [];
        $updates = $request->input('updates');

        foreach (is_array($updates) ? $updates : [] as $update) {
            if (! is_array($update) || ($update['type'] ?? null) !== 'callMethod') {
                continue;
            }

            $method = is_array($update['payload'] ?? null) ? ($update['payload']['method'] ?? null) : null;

            if (is_string($method) && $method !== '') {
                $methods[] = $method;
            }
        }

        return $name === null && $methods === [] ? [] : [[$name, $methods]];
    }
}
