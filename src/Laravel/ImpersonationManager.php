<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Psr\Clock\ClockInterface;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthAdapter;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Impersonator\Core\Contracts\ImpersonationDriver;
use Simtabi\Laranail\Impersonator\Core\Contracts\ModeEnforcer;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationException;
use Simtabi\Laranail\Impersonator\Core\Support\ModeRegistry;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\ExtensionGrant;
use Simtabi\Laranail\Impersonator\Core\Values\ExtensionOutcome;
use Simtabi\Laranail\Impersonator\Core\Values\ExtensionPolicy;
use Simtabi\Laranail\Impersonator\Core\Values\Guards;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Laravel\Services\ImpersonationService;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Laravel\Support\ReviewerDirectory;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Simtabi\Laranail\Impersonator\Laravel\Support\TargetRegistry;

/**
 * The facade root, and the point where the two orthogonal axes compose.
 *
 * Drivers answer where an impersonation happens; adapters answer what
 * authenticating the target consists of. Neither knows about the other, and this
 * class is what pairs them — which is why adding a driver never requires
 * touching an adapter, and why `token` + `sanctum` works without anyone having
 * written that combination.
 *
 * Both registries take closures resolved lazily and cached per name, so an
 * installation that has Passport installed but configured to `session` never
 * constructs the Passport adapter.
 */
class ImpersonationManager
{
    /** @var array<string, Closure(Container): ImpersonationDriver> */
    protected array $driverFactories = [];

    /** @var array<string, ImpersonationDriver> */
    protected array $resolvedDrivers = [];

    /** @var array<string, Closure(Container): AuthAdapter> */
    protected array $adapterFactories = [];

    /** @var array<string, AuthAdapter> */
    protected array $resolvedAdapters = [];

    /** Overrides accept-URL construction for addressing schemes config cannot express. */
    protected ?Closure $acceptUrlResolver = null;

    /** Overrides how a target is labelled in the banner. */
    protected ?Closure $displayNameResolver = null;

    /** Overrides how the RBAC layer is detected, for a rule config cannot express. */
    protected ?Closure $rbacDetector = null;

    public function __construct(
        protected Container $app,
        protected Config $config,
        protected ModeRegistry $modeRegistry,
        protected IdentityResolver $identities,
    ) {}

    // ── Registration ────────────────────────────────────────────────────────

    /**
     * Register a driver. Overwrites a built-in of the same name, which is the
     * supported way to replace one wholesale.
     *
     * @param Closure(Container): ImpersonationDriver $factory
     */
    public function extend(string $name, Closure $factory): self
    {
        $this->driverFactories[$name] = $factory;
        unset($this->resolvedDrivers[$name]);

        return $this;
    }

    /** @param Closure(Container): AuthAdapter $factory */
    public function extendAdapter(string $name, Closure $factory): self
    {
        $this->adapterFactories[$name] = $factory;
        unset($this->resolvedAdapters[$name]);

        return $this;
    }

    /** Register a custom mode, the documented extension point for modes. */
    /**
     * Decide for yourself whether an RBAC layer is present.
     *
     * The default probes a configurable list of class names (`authorization.rbac.detect`), which
     * covers swapping one permission package for another. This is for the cases a class list cannot
     * express — a capability check, an environment flag, a per-tenant decision.
     *
     * Register it in a provider's `boot()`, before anything resolves the policy:
     *
     *   Impersonator::detectRbacUsing(fn (): bool => MyPermissions::isEnabled());
     *
     * **Fails closed.** Anything other than a literal `true` selects the base policy, including a
     * truthy string and a thrown exception. A detector that errors must not be read as "yes, this
     * application has permissions" — that would hand the RBAC policy a permission system it cannot
     * query, and a policy that cannot query its permissions is one that cannot enforce them.
     *
     * @param Closure(): mixed $detector
     */
    public function detectRbacUsing(Closure $detector): self
    {
        $this->rbacDetector = $detector;

        return $this;
    }

    /**
     * Whether an RBAC layer is present, and so whether the RBAC policy should be selected.
     *
     * Detected by provider class rather than by a trait on the user model: the model may not be
     * loaded at this point, and a provider's presence is the reliable signal that the package is
     * wired in rather than merely sitting in the vendor directory.
     *
     * An explicit `authorization.policy` wins over this entirely — it is only consulted to choose a
     * default.
     */
    public function detectsRbac(): bool
    {
        if ($this->rbacDetector !== null) {
            try {
                return ($this->rbacDetector)() === true;
            } catch (\Throwable) {
                // Fail closed, as above. The base policy still enforces every identity rule; what is
                // lost is the permission layer, which a detector that just threw cannot be trusted
                // to describe anyway.
                return false;
            }
        }

        return array_any($this->rbacDetectionClasses(), fn (string $class): bool => class_exists($class) || interface_exists($class));
    }

    /**
     * The class names probed by the default detector.
     *
     * Defaults to spatie/laravel-permission's provider, which is the package the RBAC policy was
     * written against — but only as a *default*. The policy itself is duck-typed against
     * `hasPermissionTo()` and `hasRole()`, so any package exposing that surface works once named
     * here; nothing about it is spatie-specific beyond this list.
     *
     * @return list<string>
     */
    protected function rbacDetectionClasses(): array
    {
        $configured = new Settings($this->config)->stringList('authorization.rbac.detect');

        return $configured === []
            ? ['Spatie\Permission\PermissionServiceProvider']
            : $configured;
    }

    /**
     * Decide for yourself whether a reviewer may decide a given request.
     *
     * The escape hatch for a rule config cannot express — *"must be the requester's line manager"*,
     * or *"not from the same team"* — a relationship this package has no business modelling. Layered
     * **on top of** the approve permission and the role slots, never instead of them:
     *
     *   Impersonator::approvalEligibilityUsing(
     *       fn (Model $reviewer, ApprovalRequest $request): bool => $reviewer->manages($request->requester),
     *   );
     *
     * **Fails closed.** Anything other than a literal `true` refuses, including a truthy string and a
     * thrown exception — the point of registering a rule is that the package cannot judge the
     * relationship itself, so a rule that errors is not consent.
     *
     * @param Closure(Model, ApprovalRequest): mixed $rule
     */
    public function approvalEligibilityUsing(Closure $rule): self
    {
        $this->app->make(ReviewerDirectory::class)->eligibilityUsing($rule);

        return $this;
    }

    public function registerMode(ModeEnforcer $enforcer): self
    {
        $this->modeRegistry->register($enforcer);

        return $this;
    }

    // ── Resolution ──────────────────────────────────────────────────────────

    /**
     * @throws ImpersonationException when the driver is unknown, or is known but
     *                                cannot run here — a misconfigured driver
     *                                fails loudly at selection rather than
     *                                silently degrading to another one.
     */
    public function driver(?string $name = null): ImpersonationDriver
    {
        $name ??= $this->defaultDriver();

        if (isset($this->resolvedDrivers[$name])) {
            return $this->resolvedDrivers[$name];
        }

        $factory = $this->driverFactories[$name] ?? throw new ImpersonationException(sprintf(
            'Impersonation driver [%s] is not registered. Available drivers: %s.',
            $name,
            $this->driverNames() === [] ? '(none)' : implode(', ', $this->driverNames()),
        ));

        $driver = $factory($this->app);

        if (! $driver->isAvailable()) {
            throw new ImpersonationException(sprintf(
                'Impersonation driver [%s] is registered but not available in this installation. '
                . 'Check that its prerequisites are installed and its migrations have run.',
                $name,
            ));
        }

        return $this->resolvedDrivers[$name] = $driver;
    }

    /** @throws ImpersonationException when the adapter is unknown or unavailable */
    public function adapter(?string $name = null): AuthAdapter
    {
        $name ??= $this->defaultAdapter();

        if (isset($this->resolvedAdapters[$name])) {
            return $this->resolvedAdapters[$name];
        }

        $factory = $this->adapterFactories[$name] ?? throw new ImpersonationException(sprintf(
            'Impersonation auth adapter [%s] is not registered. Available adapters: %s.',
            $name,
            $this->adapterNames() === [] ? '(none)' : implode(', ', $this->adapterNames()),
        ));

        $adapter = $factory($this->app);

        if (! $adapter->isAvailable()) {
            throw new ImpersonationException(sprintf(
                'Impersonation auth adapter [%s] is registered but not available in this '
                . 'installation. Either its underlying package is not installed, or the '
                . 'configured guard [%s] is not of a driver it can authenticate.',
                $name,
                $this->configString('impersonator.guards.target', 'web'),
            ));
        }

        return $this->resolvedAdapters[$name] = $adapter;
    }

    /**
     * The configured driver, resolving `auto`.
     *
     * `auto` picks tenancy when a tenant is initialized and session otherwise.
     * An explicit config value is never second-guessed — the automatic choice
     * exists to spare a single-purpose app a decision, not to override one an
     * operator made deliberately.
     */
    public function defaultDriver(): string
    {
        $configured = $this->configString('impersonator.driver', 'session');

        if ($configured !== 'auto') {
            return $configured;
        }

        return $this->tenancyIsInitialized() ? 'tenancy' : 'session';
    }

    public function defaultAdapter(): string
    {
        return $this->configString('impersonator.adapter', 'session');
    }

    public function modes(): ModeRegistry
    {
        return $this->modeRegistry;
    }

    /** @return list<string> */
    public function driverNames(): array
    {
        return array_keys($this->driverFactories);
    }

    /** @return list<string> */
    public function adapterNames(): array
    {
        return array_keys($this->adapterFactories);
    }

    public function hasDriver(string $name): bool
    {
        return isset($this->driverFactories[$name]);
    }

    public function hasAdapter(string $name): bool
    {
        return isset($this->adapterFactories[$name]);
    }

    /**
     * Drivers registered and actually usable here, for the doctor command.
     *
     * @return array<string, bool>
     */
    public function driverAvailability(): array
    {
        $availability = [];

        foreach ($this->driverFactories as $name => $factory) {
            try {
                $availability[$name] = $factory($this->app)->isAvailable();
            } catch (\Throwable) {
                $availability[$name] = false;
            }
        }

        return $availability;
    }

    /** @return array<string, bool> */
    public function adapterAvailability(): array
    {
        $availability = [];

        foreach ($this->adapterFactories as $name => $factory) {
            try {
                $availability[$name] = $factory($this->app)->isAvailable();
            } catch (\Throwable) {
                $availability[$name] = false;
            }
        }

        return $availability;
    }

    // ── Lifecycle ───────────────────────────────────────────────────────────

    /**
     * Begin impersonating a target.
     *
     * Returns an outcome rather than a session because not every driver finishes
     * in one request: a same-app driver has the target authenticated by the time
     * this returns, while a cross-domain driver has only issued a token and a
     * URL that still has to be followed.
     *
     * @param array<string, mixed> $metadata
     *
     * @throws ImpersonationDenied when any rule in the authorization stack refuses
     */
    public function enter(
        Authenticatable|Model $target,
        string|Mode|null $mode = null,
        ?string $reason = null,
        ?string $redirectTo = null,
        Authenticatable|Model|null $impersonator = null,
        ?string $driver = null,
        ?string $adapter = null,
        array $metadata = [],
    ): ImpersonationOutcome {
        return $this->service()->enter(
            target: $target,
            mode: $mode,
            reason: $reason,
            redirectTo: $redirectTo,
            impersonator: $impersonator,
            driver: $driver,
            adapter: $adapter,
            metadata: $metadata,
        );
    }

    /**
     * Complete a handoff that `enter()` only started, by redeeming its token.
     *
     * The policy runs again here rather than trusting the decision made at issue
     * time: permissions can be withdrawn, a role can change, and the audit row
     * can be revoked in the seconds between minting a token and following it.
     */
    public function complete(string $token, ?string $driver = null): ImpersonationOutcome
    {
        return $this->service()->complete($token, $driver);
    }

    /** End the current impersonation. Always available, and only de-escalating. */
    public function leave(EndReason $reason = EndReason::Left, ?string $driver = null): ?ImpersonationSession
    {
        return $this->service()->leave($reason, $driver);
    }

    /**
     * Buy more time on the current impersonation, without leaving it.
     *
     * Note this is **not** `extend()` — that is Laravel's driver-registration method, inherited
     * from the Manager convention this class follows. The two are unrelated: `extend()` teaches
     * the manager a new driver, `extendSession()` moves a live impersonation's deadline.
     *
     * Never throws for a refusal. "You have used all three extensions" is an answer a UI has to
     * render, not an exception, and an operator learning they cannot extend still needs the page
     * they were on.
     */
    public function extendSession(?ExtensionPolicy $policy = null): ExtensionOutcome
    {
        return $this->service()->extendSession($policy);
    }

    /**
     * Whether the current impersonation could be extended right now, and until when.
     *
     * Read-only, and cheap: it evaluates the same rules against the session already in hand
     * without a lock or a write, so a Blade view can call it to decide whether to render the
     * button. The authoritative answer is still the one `extendSession()` returns from inside
     * its transaction — between rendering a button and clicking it, another request may have
     * spent the last extension.
     */
    public function canExtendSession(): ExtensionGrant
    {
        $session = $this->current();

        if ($session === null) {
            return ExtensionGrant::refuse(Decision::deny(
                Decision::NOT_IMPERSONATING,
                'There is no active impersonation to extend.',
            ));
        }

        return $this->extensionPolicy()->evaluate($session, $this->app->make(ClockInterface::class)->now());
    }

    /**
     * The configured extension rules.
     *
     * Built per call rather than cached, so a test or a runtime config change takes effect —
     * it is five config reads and a constructor.
     */
    public function extensionPolicy(): ExtensionPolicy
    {
        $settings = new Settings($this->config);

        return new ExtensionPolicy(
            enabled: $settings->bool('limits.extension.enabled', true),
            // Floored at one: a zero-minute extension would report success and move nothing,
            // which reads as the button being broken.
            minutes: max(1, $settings->int('limits.extension.minutes', 10)),
            max: $settings->positiveIntOrNull('limits.extension.max'),
            maxTotalMinutes: $settings->positiveIntOrNull('limits.extension.max_total_duration'),
            withinMinutes: $settings->positiveIntOrNull('limits.extension.within'),
        );
    }

    /** End an impersonation the caller does not own — the kill switch. */
    public function revoke(string $auditId, ?Identity $revokedBy = null, ?string $note = null): ImpersonationSession
    {
        return $this->service()->revoke($auditId, $revokedBy, $note);
    }

    /** The impersonation active in this context, read from server-side state only. */
    public function current(): ?ImpersonationSession
    {
        try {
            return $this->driver()->current();
        } catch (ImpersonationException) {
            // A driver that cannot even be constructed cannot be impersonating.
            // Reporting "no active impersonation" is the safe reading, and it
            // keeps a misconfigured driver from breaking a Blade directive on
            // every page of the application.
            return null;
        }
    }

    public function isImpersonating(): bool
    {
        return $this->current() !== null;
    }

    /**
     * The operator behind the current request — the impersonator while an
     * impersonation is active, and the authenticated user otherwise.
     *
     * This is the correctness fix that makes attribution right. During
     * impersonation `auth()->user()` is the target, so anything that records a
     * causer from the auth context blames the target for the operator's actions.
     * Use this wherever the question is "who really did this".
     */
    public function actor(): Authenticatable|Model|null
    {
        $session = $this->current();

        if ($session === null) {
            return $this->authenticated();
        }

        return $this->identities->resolveActor($session->impersonator) ?? $this->authenticated();
    }

    /** The target being impersonated, or null. */
    public function target(): Authenticatable|Model|null
    {
        $session = $this->current();

        return $session === null ? null : $this->identities->toUser($session->target);
    }

    /** The active mode, or null when not impersonating. */
    public function mode(): ?Mode
    {
        return $this->current()?->mode;
    }

    // ── Extension hooks ─────────────────────────────────────────────────────

    /**
     * Override accept-URL construction, for identification schemes the `urls`
     * config cannot express.
     *
     * Receives the ImpersonationRequest and the raw token; must return an
     * absolute URL. The token is a live single-use secret — do not log it.
     */
    public function resolveAcceptUrlUsing(Closure $resolver): self
    {
        $this->acceptUrlResolver = $resolver;

        return $this;
    }

    public function hasAcceptUrlResolver(): bool
    {
        return $this->acceptUrlResolver instanceof Closure;
    }

    public function callAcceptUrlResolver(ImpersonationRequest $request, string $token): string
    {
        if (! $this->acceptUrlResolver instanceof Closure) {
            throw new ImpersonationException('No accept URL resolver has been registered.');
        }

        $url = ($this->acceptUrlResolver)($request, $token);

        if (! is_string($url) || $url === '') {
            throw new ImpersonationException(
                'The accept URL resolver must return a non-empty absolute URL string.',
            );
        }

        return $url;
    }

    /** Override how the target is labelled in the banner. */
    public function displayNameUsing(Closure $resolver): self
    {
        $this->displayNameResolver = $resolver;

        return $this;
    }

    public function displayNameFor(Authenticatable|Model|null $user): ?string
    {
        if ($user === null) {
            return null;
        }

        if ($this->displayNameResolver instanceof Closure) {
            $name = ($this->displayNameResolver)($user);

            return is_scalar($name) ? (string) $name : null;
        }

        $attribute = ($user instanceof Model
            ? $this->identities->targets()->forModel($user)?->displayName
            : null)
            ?? $this->config->get('impersonator.banner.display_name', 'name');

        if (is_string($attribute) && $user instanceof Model) {
            $value = $user->getAttribute($attribute);

            if (is_scalar($value)) {
                return (string) $value;
            }
        }

        return null;
    }

    // ── Internals ───────────────────────────────────────────────────────────

    /**
     * Assemble a fully-resolved request. Validation of the mode happens here, so
     * an unregistered mode is refused before any authorization or persistence
     * work is attempted.
     *
     * @param array<string, mixed> $metadata
     */
    public function buildRequest(
        Authenticatable|Model $target,
        string|Mode|null $mode = null,
        ?string $reason = null,
        ?string $redirectTo = null,
        Authenticatable|Model|null $impersonator = null,
        ?string $driver = null,
        ?string $adapter = null,
        array $metadata = [],
    ): ImpersonationRequest {
        $impersonator ??= $this->authenticated();

        if ($impersonator === null) {
            throw new ImpersonationException(
                'Cannot impersonate without an authenticated impersonator. '
                . 'Pass one explicitly when entering outside an HTTP request.',
            );
        }

        $targetIdentity = $this->identities->fromUser($target);

        return new ImpersonationRequest(
            impersonator: $this->identities->fromUser($impersonator),
            target: $targetIdentity,
            mode: $this->resolveMode($mode),
            guards: $this->guardsFor($targetIdentity->type),
            driver: $driver ?? $this->defaultDriver(),
            adapter: $adapter ?? $this->defaultAdapter(),
            reason: $reason,
            redirectTo: $redirectTo,
            tenantId: $this->currentTenantId(),
            ip: $this->requestIp(),
            userAgent: $this->requestUserAgent(),
            metadata: $metadata,
        );
    }

    public function resolveMode(string|Mode|null $mode): Mode
    {
        if ($mode instanceof Mode) {
            return $this->modeRegistry->resolve($mode->name);
        }

        return $this->modeRegistry->resolve(
            $mode ?? $this->configString('impersonator.default_mode', Mode::FULL),
        );
    }

    public function guards(): Guards
    {
        return new Guards(
            impersonator: $this->impersonatorGuardName(),
            target: $this->configString('impersonator.guards.target', 'web'),
        );
    }

    /**
     * The guard pair for a specific target type.
     *
     * This is what makes more than one impersonatable model actually work. A marketplace
     * with customers on `web` and vendors on `vendor` cannot be described by a single
     * global target guard — and authenticating a vendor against the customer provider
     * would either fail confusingly or, worse, find a different account with the same id.
     * A type that declares no guard falls back to the global setting, so single-model
     * installations are unaffected.
     */
    public function guardsFor(string $targetType): Guards
    {
        $fallback = $this->configString('impersonator.guards.target', 'web');

        return new Guards(
            impersonator: $this->impersonatorGuardName(),
            target: $this->identities->typeFor($targetType)?->guardOr($fallback) ?? $fallback,
        );
    }

    /**
     * Register an impersonatable account type at runtime.
     *
     * The extension point for a package that ships its own type — a vendor module
     * registering `vendor` from its own service provider — without asking the host
     * application to edit config it does not own. A runtime registration overrides config
     * of the same alias, so the host can always take back control.
     */
    public function registerTarget(
        string $alias,
        string $model,
        ?string $guard = null,
        ?string $displayName = null,
        ?string $label = null,
    ): self {
        $this->identities->targets()->register($alias, $model, $guard, $displayName, $label);

        return $this;
    }

    /** The registered account types, alias => type. */
    public function targets(): TargetRegistry
    {
        return $this->identities->targets();
    }

    public function identities(): IdentityResolver
    {
        return $this->identities;
    }

    public function policy(): AuthorizationPolicy
    {
        return $this->app->make(AuthorizationPolicy::class);
    }

    protected function events(): Dispatcher
    {
        return $this->app->make(Dispatcher::class);
    }

    /**
     * The orchestration layer.
     *
     * Resolved lazily rather than injected: the service needs the manager to pick a
     * driver, so constructor-injecting it here would close the loop at build time.
     */
    public function service(): ImpersonationService
    {
        return $this->app->make(ImpersonationService::class);
    }

    public function auditStore(): AuditStore
    {
        return $this->app->make(AuditStore::class);
    }

    /**
     * Whether this target could be impersonated right now, without doing it.
     *
     * Runs the identical policy `enter()` runs, which is the point: a UI that hides
     * its impersonate button using different logic from the one that authorizes the
     * action will eventually show a button that 403s, or hide one that would have
     * worked.
     *
     * Never throws — an unresolvable impersonator or an invalid mode comes back as
     * a denial, because a template asking "may I?" should get an answer.
     */
    public function canImpersonate(
        Authenticatable|Model $target,
        string|Mode|null $mode = null,
        Authenticatable|Model|null $impersonator = null,
        ?string $reason = null,
    ): Decision {
        try {
            $request = $this->buildRequest(
                target: $target,
                mode: $mode,
                reason: $reason,
                impersonator: $impersonator,
            );
        } catch (ImpersonationException $e) {
            return Decision::deny(Decision::IMPERSONATOR_NOT_PERMITTED, $e->getMessage());
        }

        return $this->policy()->authorize($request);
    }

    /**
     * Whether an operator may use a mode, for building a UI that offers only the
     * modes they actually hold.
     */
    public function canUseMode(string|Mode $mode, Authenticatable|Model|null $impersonator = null): Decision
    {
        $impersonator ??= $this->authenticated();

        if ($impersonator === null) {
            return Decision::deny(
                Decision::IMPERSONATOR_NOT_PERMITTED,
                'There is no authenticated user to check a mode against.',
                ['detail' => 'unauthenticated'],
            );
        }

        return $this->policy()->authorizeMode(
            $this->identities->fromUser($impersonator),
            $mode instanceof Mode ? $mode->name : $mode,
        );
    }

    protected function authenticated(): Authenticatable|Model|null
    {
        return $this->app->make(AuthFactory::class)
            ->guard($this->impersonatorGuardName())
            ->user();
    }

    protected function impersonatorGuardName(): string
    {
        return $this->configString('impersonator.guards.impersonator', 'web');
    }

    /**
     * The current tenant key, when a tenancy package is installed and initialized.
     * Kept behind function_exists so tenancy stays an optional driver rather
     * than a requirement.
     */
    protected function currentTenantId(): ?string
    {
        if (! function_exists('tenant')) {
            return null;
        }

        $tenant = tenant();

        if (! is_object($tenant) || ! method_exists($tenant, 'getTenantKey')) {
            return null;
        }

        $key = $tenant->getTenantKey();

        return is_scalar($key) ? (string) $key : null;
    }

    protected function tenancyIsInitialized(): bool
    {
        return $this->currentTenantId() !== null;
    }

    protected function requestIp(): ?string
    {
        return $this->request()?->ip();
    }

    protected function requestUserAgent(): ?string
    {
        $agent = $this->request()?->userAgent();

        // Bounded before it reaches the audit row: a user agent is
        // attacker-controlled and arrives at whatever length the client chose.
        return $agent === null ? null : mb_substr($agent, 0, 512);
    }

    /** Null outside an HTTP context — the CLI enter command has no request. */
    protected function request(): ?Request
    {
        return $this->app->bound('request') ? $this->app->make(Request::class) : null;
    }

    /**
     * Read a string setting, refusing anything else.
     *
     * A guard, driver or mode name that arrived as an array or null is a
     * misconfiguration, and quietly substituting the default would resolve it to
     * some guard other than the one the operator intended — so it fails here.
     * The default applies only when the key is genuinely absent.
     */
    protected function configString(string $key, string $default): string
    {
        $value = $this->config->get($key, $default);

        if (is_string($value) && $value !== '') {
            return $value;
        }

        throw new ImpersonationException(sprintf(
            'Config [%s] must be a non-empty string, %s given.',
            $key,
            get_debug_type($value),
        ));
    }

    /**
     * The authenticated operator, or null. Public so a Form Request can require one
     * without duplicating the guard lookup.
     */
    public function currentImpersonatorOrNull(): Authenticatable|Model|null
    {
        return $this->authenticated();
    }

    /** The impersonator on the active session, or null. */
    public function currentImpersonatorIdentity(): ?Identity
    {
        return $this->current()?->impersonator;
    }

    /**
     * A rate-limit key naming whoever is really making this request.
     *
     * Laravel keys `throttle` on `$request->user()`, which during an impersonation is the target — so
     * an operator's traffic is billed to the customer's quota, and an operator can deliberately
     * exhaust a chosen customer's limit. Rate limits exist to bound a *caller*, and the caller is the
     * person who authenticated, not the account they are viewing.
     *
     * Returns null when nobody is impersonating, which lets a caller fall back to whatever it would
     * otherwise have used — the framework's own signature, or `$request->user()?->getAuthIdentifier()`
     * in a named limiter:
     *
     *     RateLimiter::for('api', fn (Request $request) => Limit::perMinute(60)->by(
     *         impersonator()->rateLimitKey($request)
     *             ?? (string) ($request->user()?->getAuthIdentifier() ?? $request->ip()),
     *     ));
     *
     * A `ThrottleByOperator` middleware ships for the `throttle:60,1` form, where the key is chosen
     * inside the framework's middleware rather than by the application.
     */
    public function rateLimitKey(?Request $request = null): ?string
    {
        $impersonator = $this->currentImpersonatorIdentity();

        if ($impersonator === null) {
            return null;
        }

        // Prefixed and keyed on the morph-qualified identity, so two models sharing an id — a
        // `User` 7 and a `Vendor` 7 — never share a limiter bucket.
        return 'impersonator-operator:' . $impersonator->key();
    }
}
