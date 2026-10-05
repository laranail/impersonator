<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

/**
 * The package's public names, and the bare spellings they replaced.
 *
 * Route names, rate limiters, gate abilities, Blade components and container aliases all live in
 * flat registries keyed by the name, so a second package claiming `impersonator.leave` or
 * `impersonator-enter` would silently replace this one. Every name the package registers is
 * therefore scoped to `laranail-impersonator`, and each bare name it shipped before keeps working as
 * a deprecated alias that announces itself once per process and forwards to its replacement.
 *
 * The bare names may stop resolving no earlier than the next minor after 0.1.
 */
final class DeprecatedNames
{
    /** The earliest release that may remove a bare name. */
    public const string REMOVAL = 'the next minor after 0.1';

    /** The route-name prefix for the package's own routes. */
    public const string ROUTE_PREFIX = 'laranail-impersonator.';

    /** The route-name prefix for the REST API. */
    public const string API_ROUTE_PREFIX = 'laranail-impersonator.api.';

    /** The bare route-name prefix every route carried before 0.1 was scoped. */
    public const string LEGACY_ROUTE_PREFIX = 'impersonator.';

    /** The container alias for the manager. */
    public const string CONTAINER_ALIAS = 'laranail.impersonator';

    /** @var array<string, string> Bare container alias => scoped alias. */
    public const array CONTAINER_ALIASES = ['impersonator' => self::CONTAINER_ALIAS];

    /** @var array<string, string> Bare rate limiter => scoped limiter. */
    public const array RATE_LIMITERS = [
        'impersonator-enter'  => 'laranail-impersonator.enter',
        'impersonator-api'    => 'laranail-impersonator.api',
        'impersonator-accept' => 'laranail-impersonator.accept',
    ];

    /** @var array<string, string> Bare gate ability => scoped ability. */
    public const array GATE_ABILITIES = [
        'impersonator.revoke'     => 'laranail-impersonator.revoke',
        'impersonator.audit.view' => 'laranail-impersonator.audit.view',
        'impersonator.mode'       => 'laranail-impersonator.mode',
    ];

    /**
     * Default RBAC permission name => the bare default it replaced.
     *
     * Keyed by the `authorization.permissions.*` config key. Only the shipped defaults have a legacy
     * spelling: an application that configured its own name gets exactly that name, unchanged.
     *
     * @var array<string, array{string, string}>
     */
    public const array PERMISSIONS = [
        'enter'      => ['laranail-impersonator.enter', 'impersonator.enter'],
        'mode'       => ['laranail-impersonator.mode.%s', 'impersonator.mode.%s'],
        'revoke'     => ['laranail-impersonator.revoke', 'impersonator.revoke'],
        'approve'    => ['laranail-impersonator.approve', 'impersonator.approve'],
        'audit_view' => ['laranail-impersonator.audit.view', 'impersonator.audit.view'],
    ];

    /** @var array<string, string> Bare Blade component tag => scoped tag. */
    public const array BLADE_COMPONENTS = [
        'impersonation-banner'       => 'laranail-impersonator::banner',
        'impersonate-button'         => 'laranail-impersonator::impersonate-button',
        'impersonation-leave-button' => 'laranail-impersonator::leave-button',
        'impersonation-badge'        => 'laranail-impersonator::badge',
        'when-impersonating'         => 'laranail-impersonator::when-impersonating',
    ];

    /**
     * Bare `vendor:publish` tag => scoped tag.
     *
     * Both are registered over the same source and destination, so either publishes the same files;
     * the bare one announces itself after it has published.
     *
     * @var array<string, string>
     */
    public const array PUBLISH_TAGS = [
        'impersonator-config'     => 'laranail::impersonator-config',
        'impersonator-views'      => 'laranail::impersonator-views',
        'impersonator-lang'       => 'laranail::impersonator-lang',
        'impersonator-migrations' => 'laranail::impersonator-migrations',
    ];

    /** @var array<string, true> "kind\0name" => announced */
    private static array $announced = [];

    /**
     * Announce, once per process, that a deprecated name was used.
     *
     * Raised as `E_USER_DEPRECATED`, which Laravel routes to its `deprecations` log channel and which
     * never interrupts the request. Once per name rather than once per call, so a banner rendered on
     * every page does not write a line per request.
     */
    public static function announce(string $kind, string $old, string $new): void
    {
        $key = $kind . "\0" . $old;

        if (isset(self::$announced[$key])) {
            return;
        }

        self::$announced[$key] = true;

        trigger_error(self::message($kind, $old, $new), E_USER_DEPRECATED);
    }

    /**
     * The notice text, so a test can assert it without depending on a handler.
     */
    public static function message(string $kind, string $old, string $new): string
    {
        return sprintf(
            '[laranail/impersonator] The %s [%s] is deprecated and will be removed no earlier than %s. Use [%s] instead.',
            $kind,
            $old,
            self::REMOVAL,
            $new,
        );
    }

    /**
     * The bare spelling of a scoped route name, or null when it has none.
     *
     * `laranail-impersonator.leave` → `impersonator.leave`. Used where a host lists route names in
     * configuration it wrote before 0.1 was scoped, such as `modes.read_only.allowed_routes`.
     */
    public static function legacyRouteName(string $name): ?string
    {
        return str_starts_with($name, self::ROUTE_PREFIX)
            ? self::LEGACY_ROUTE_PREFIX . substr($name, strlen(self::ROUTE_PREFIX))
            : null;
    }

    /**
     * Forget which names were announced. For test suites; a process announces each name once.
     */
    public static function forgetWarnings(): void
    {
        self::$announced = [];
    }
}
