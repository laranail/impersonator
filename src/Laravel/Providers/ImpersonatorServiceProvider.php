<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Contracts\Session\Session;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Console\AboutCommand;
use Illuminate\Http\Request;
use Illuminate\Log\LogManager;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Psr\Clock\ClockInterface;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthAdapter;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Impersonator\Core\Contracts\FailureReporter;
use Simtabi\Laranail\Impersonator\Core\Contracts\ImpersonationDriver;
use Simtabi\Laranail\Impersonator\Core\Contracts\TokenRepository;
use Simtabi\Laranail\Impersonator\Core\Contracts\TrailStore;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalDenied;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalGranted;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalRequested;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationEnded;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationExpired;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRejected;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRevoked;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationStarted;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ApprovalNotDecidable;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ApprovalRequired;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Exceptions\TokenRejected;
use Simtabi\Laranail\Impersonator\Core\Support\AuditChain;
use Simtabi\Laranail\Impersonator\Core\Support\FailurePolicy;
use Simtabi\Laranail\Impersonator\Core\Support\FailureReport;
use Simtabi\Laranail\Impersonator\Core\Support\ModeRegistry;
use Simtabi\Laranail\Impersonator\Laravel\Adapters\JwtAdapter;
use Simtabi\Laranail\Impersonator\Laravel\Adapters\PassportAdapter;
use Simtabi\Laranail\Impersonator\Laravel\Adapters\SanctumTokenAdapter;
use Simtabi\Laranail\Impersonator\Laravel\Adapters\SessionGuardAdapter;
use Simtabi\Laranail\Impersonator\Laravel\Approval\EloquentApprovalStore;
use Simtabi\Laranail\Impersonator\Laravel\Audit\ConcurrencyLimitReached;
use Simtabi\Laranail\Impersonator\Laravel\Audit\EloquentAuditStore;
use Simtabi\Laranail\Impersonator\Laravel\Audit\EloquentTrailStore;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\BasePolicy;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Commands\DoctorCommand;
use Simtabi\Laranail\Impersonator\Laravel\Commands\EnterCommand;
use Simtabi\Laranail\Impersonator\Laravel\Commands\ExportAuditCommand;
use Simtabi\Laranail\Impersonator\Laravel\Commands\PruneApprovalsCommand;
use Simtabi\Laranail\Impersonator\Laravel\Commands\PruneTokensCommand;
use Simtabi\Laranail\Impersonator\Laravel\Commands\VerifyAuditCommand;
use Simtabi\Laranail\Impersonator\Laravel\Drivers\SessionDriver;
use Simtabi\Laranail\Impersonator\Laravel\Drivers\TenancyDriver;
use Simtabi\Laranail\Impersonator\Laravel\Drivers\TokenDriver;
use Simtabi\Laranail\Impersonator\Laravel\Failure\LaravelFailureReporter;
use Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\LeaveImpersonationController;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Listeners\LogImpersonationLifecycle;
use Simtabi\Laranail\Impersonator\Laravel\Listeners\SendImpersonationNotifications;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\EnforceImpersonationMode;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\GuardImpersonationLifetime;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\RecordImpersonationTrail;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Laravel\Modes\FullModeEnforcer;
use Simtabi\Laranail\Impersonator\Laravel\Modes\LimitedModeEnforcer;
use Simtabi\Laranail\Impersonator\Laravel\Modes\ReadOnlyModeEnforcer;
use Simtabi\Laranail\Impersonator\Laravel\Policies\ImpersonationAuditPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Support\BannerPresenter;
use Simtabi\Laranail\Impersonator\Laravel\Support\CauserResolver;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Laravel\Support\LaravelClock;
use Simtabi\Laranail\Impersonator\Laravel\Support\RedirectGuard;
use Simtabi\Laranail\Impersonator\Laravel\Support\SessionState;
use Simtabi\Laranail\Impersonator\Laravel\Support\SessionTerminator;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Simtabi\Laranail\Impersonator\Laravel\Support\TargetRegistry;
use Simtabi\Laranail\Impersonator\Laravel\Tokens\AcceptUrlBuilder;
use Simtabi\Laranail\Impersonator\Laravel\Tokens\EloquentTokenRepository;
use Simtabi\Laranail\Impersonator\Laravel\View\Components\ImpersonateButton;
use Simtabi\Laranail\Impersonator\Laravel\View\Components\ImpersonationBadge;
use Simtabi\Laranail\Impersonator\Laravel\View\Components\ImpersonationBanner;
use Simtabi\Laranail\Impersonator\Laravel\View\Components\LeaveImpersonationButton;
use Simtabi\Laranail\Impersonator\Laravel\View\Components\WhenImpersonating;
use Spatie\Permission\PermissionServiceProvider;

/**
 * The bridge's entry point.
 *
 * Not deferrable: the package installs request-scoped enforcement, so it boots on
 * every request whether or not anything touches the manager.
 *
 * `register()` binds only and `boot()` wires anything that reads config or reaches
 * for another package, so nothing here depends on another provider's boot order.
 */
class ImpersonatorServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom($this->configPath(), 'impersonator');

        $this->registerSupport();
        $this->registerContracts();
        $this->registerManager();
    }

    /**
     * Boot, with every operation classified per the failure-handling standard.
     *
     * Ordered critical-first and run through one policy, so a degradable failure never
     * leaves a later operation depending on a capability that was silently dropped. No
     * environment check appears anywhere: a failure unsafe to continue past crashes in
     * development and in production alike, which is the only way the test suite
     * exercises what actually ships.
     *
     * The classifications are the reviewable decisions:
     *
     *  - **Critical** — drivers and adapters (nothing works without them), middleware
     *    (a mode or a revocation that fails to register enforces nothing, silently),
     *    gates, and exception rendering (its absence leaks internal detail into
     *    responses).
     *  - **Degradable** — routes (an app may register its own), views, Blade directives
     *    and components (cosmetic: a missing banner is bad, but it is not insecure),
     *    the route macro (sugar), listeners (logging), and publishing (console only).
     */
    public function boot(): void
    {
        $failures = $this->app->make(FailurePolicy::class);

        $failures->critical('impersonator.boot.drivers', $this->registerDriversAndAdapters(...));
        $failures->critical('impersonator.boot.middleware', $this->registerMiddleware(...));
        $failures->critical('impersonator.boot.gates', $this->registerGates(...));
        $failures->critical('impersonator.boot.rate_limiters', $this->registerRateLimiters(...));
        $failures->critical('impersonator.boot.exception_rendering', $this->registerExceptionRendering(...));

        $failures->degradable('impersonator.boot.routes', $this->registerRoutes(...));
        $failures->degradable('impersonator.boot.views', $this->registerViews(...));
        $failures->degradable('impersonator.boot.blade_directives', $this->registerBladeDirectives(...));
        $failures->degradable('impersonator.boot.blade_components', $this->registerBladeComponents(...));
        $failures->degradable('impersonator.boot.route_macro', $this->registerRouteMacro(...));
        $failures->degradable('impersonator.boot.listeners', $this->registerEventListeners(...));

        if ($this->app->runningInConsole()) {
            $failures->degradable('impersonator.boot.commands', $this->registerCommands(...));
            $failures->degradable('impersonator.boot.publishing', $this->registerPublishing(...));
            $failures->degradable('impersonator.boot.about', $this->registerAboutCommand(...));
        }
    }

    // ── Bindings ────────────────────────────────────────────────────────────

    protected function registerSupport(): void
    {
        // One registry per application: custom modes registered by an app's own
        // provider have to be visible to every consumer of the manager.
        //
        // All three built-ins, each paired with the middleware that enforces it — a
        // mode selectable before it was enforced would report a restriction it was
        // not applying, which is worse than not offering it at all.
        $this->app->singleton(ModeRegistry::class, static fn (Application $app): ModeRegistry => new ModeRegistry([
            new ReadOnlyModeEnforcer($app->make(Settings::class)),
            new LimitedModeEnforcer($app->make(Settings::class)),
            new FullModeEnforcer,
        ]));

        // The observable degraded-state surface. One instance per application so the
        // doctor command, a health route and the CI gate all read the same facts.
        $this->app->singleton(FailureReport::class, static fn (): FailureReport => new FailureReport);

        $this->app->singleton(
            FailureReporter::class,
            static fn (Application $app): FailureReporter => new LaravelFailureReporter(
                $app->make(ExceptionHandler::class),
                $app->make(LogManager::class),
            ),
        );

        $this->app->singleton(
            FailurePolicy::class,
            static fn (Application $app): FailurePolicy => new FailurePolicy(
                $app->make(FailureReporter::class),
                $app->make(FailureReport::class),
            ),
        );

        // PSR-20, so every expiry decision in the package answers against the same
        // clock the rest of the application uses — including a mocked one.
        $this->app->singleton(ClockInterface::class, static fn (): ClockInterface => new LaravelClock);

        $this->app->singleton(
            Settings::class,
            static fn (Application $app): Settings => new Settings($app->make(Config::class)),
        );

        // Singleton: runtime registrations from other providers have to be visible to
        // every consumer, and a fresh registry per resolution would lose them.
        $this->app->singleton(
            TargetRegistry::class,
            static fn (Application $app): TargetRegistry => new TargetRegistry($app->make(Settings::class)),
        );

        $this->app->singleton(
            IdentityResolver::class,
            static fn (Application $app): IdentityResolver => new IdentityResolver(
                $app->make(Config::class),
                $app->make(TargetRegistry::class),
            ),
        );

        $this->app->singleton(
            RedirectGuard::class,
            static fn (Application $app): RedirectGuard => new RedirectGuard($app->make(Config::class)),
        );

        // Not a singleton: the session is request-scoped, and a cached state
        // object would read a previous request's session in a long-lived worker.
        $this->app->bind(
            SessionState::class,
            static fn (Application $app): SessionState => new SessionState(
                $app->make(Session::class),
                $app->make(Config::class),
            ),
        );

        // Not a singleton: it reads the request-scoped session store, and a cached
        // instance would hold a previous request's session in a long-lived worker.
        $this->app->bind(
            AcceptUrlBuilder::class,
            static fn (Application $app): AcceptUrlBuilder => new AcceptUrlBuilder(
                $app->make(Settings::class),
                $app->make(ImpersonationManager::class),
            ),
        );

        $this->app->bind(
            SessionTerminator::class,
            static fn (Application $app): SessionTerminator => new SessionTerminator(
                $app->make(Session::class),
                $app->make(Settings::class),
                $app->make(FailureReporter::class),
            ),
        );

        $this->app->bind(
            CauserResolver::class,
            static fn (Application $app): CauserResolver => new CauserResolver(
                $app->make(ImpersonationManager::class),
                $app->make(Settings::class),
            ),
        );

        $this->app->bind(
            BannerPresenter::class,
            static fn (Application $app): BannerPresenter => new BannerPresenter(
                $app->make(ImpersonationManager::class),
                $app->make(Settings::class),
                $app->make(UrlGenerator::class),
                $app->make(Router::class),
                $app->make(ViewFactory::class),
            ),
        );
    }

    protected function registerContracts(): void
    {
        $this->app->singleton(
            AuditStore::class,
            fn (Application $app): AuditStore => new EloquentAuditStore(
                settings: $app->make(Settings::class),
                cache: $app->make(Cache::class),
                connection: $app->make(ConnectionInterface::class),
                chain: $this->auditChain($app->make(Settings::class)),
            ),
        );

        $this->app->singleton(
            TokenRepository::class,
            static fn (Application $app): TokenRepository => new EloquentTokenRepository(
                $app->make(ConnectionResolverInterface::class),
                $app->make(Settings::class),
                $app->make(ClockInterface::class),
            ),
        );

        $this->app->singleton(
            TrailStore::class,
            static fn (Application $app): TrailStore => new EloquentTrailStore(
                $app->make(FailureReporter::class),
            ),
        );

        $this->app->singleton(
            ApprovalStore::class,
            static fn (Application $app): ApprovalStore => new EloquentApprovalStore(
                $app->make(ClockInterface::class),
            ),
        );

        $this->app->bind(
            AuthAdapter::class,
            static fn (Application $app): AuthAdapter => $app->make(ImpersonationManager::class)->adapter(),
        );

        $this->app->bind(
            AuthorizationPolicy::class,
            fn (Application $app): AuthorizationPolicy => $this->makePolicy($app),
        );
    }

    /**
     * Build the authorization policy.
     *
     * The RBAC layer is selected automatically when a permission package is installed,
     * because an application that has one almost certainly wants its permissions to
     * govern impersonation — and silently ignoring them would be the more surprising
     * default. An explicit `authorization.policy` always wins.
     */
    protected function makePolicy(Application $app): AuthorizationPolicy
    {
        $settings = $app->make(Settings::class);
        $configured = $settings->nullableString('authorization.policy');

        $class = match (true) {
            $configured !== null => $configured,
            $this->rbacPackageInstalled() => RbacPolicy::class,
            default => BasePolicy::class,
        };

        if (! is_a($class, AuthorizationPolicy::class, true)) {
            throw new \InvalidArgumentException(sprintf(
                'Config [impersonator.authorization.policy] must name a class implementing %s, got [%s].',
                AuthorizationPolicy::class,
                $class,
            ));
        }

        // Resolved through the container so a custom policy can declare its own
        // dependencies, with these bound for the two that ship.
        $policy = $app->make($class, [
            'gate' => $app->make(Gate::class),
            'audits' => $app->make(AuditStore::class),
            'identities' => $app->make(IdentityResolver::class),
            'modes' => $app->make(ModeRegistry::class),
            'state' => $app->make(SessionState::class),
            'settings' => $settings,
        ]);

        // The is_a check above proves the class implements the contract; this proves the
        // container actually handed one back, since a bound override could return
        // anything at all.
        if (! $policy instanceof AuthorizationPolicy) {
            throw new \InvalidArgumentException(sprintf(
                'The container resolved [%s] to something that is not a %s.',
                $class,
                AuthorizationPolicy::class,
            ));
        }

        return $policy;
    }

    /**
     * Detected by provider class, not by a trait on the user model: the model may not be
     * loaded yet at this point, and the provider's presence is the reliable signal that
     * the package is actually wired in rather than merely in the vendor directory.
     */
    protected function rbacPackageInstalled(): bool
    {
        return class_exists(PermissionServiceProvider::class);
    }

    /**
     * The tamper-evidence chain, or null when the feature is off.
     *
     * A method rather than a container binding: the value is legitimately nullable, and a
     * container entry that resolves to null has to be keyed under something invented — which then
     * types as `mixed` at every call site.
     */
    protected function auditChain(Settings $settings): ?AuditChain
    {
        if (! $settings->bool('audit.tamper_evident', false)) {
            return null;
        }

        $key = $settings->nullableString('audit.hash_key');

        if ($key === null) {
            // Deliberately loud. A chain written with a key nobody recorded cannot be verified
            // later, so silently deriving one would produce an audit trail that only *looks*
            // tamper-evident.
            throw new \InvalidArgumentException(
                'impersonator.audit.tamper_evident is on but impersonator.audit.hash_key is not set. '
                . 'Set a long random key, keep it outside the database, and do not rotate it without '
                . 're-verifying: the chain cannot be checked without the key it was written with.',
            );
        }

        return new AuditChain($key);
    }

    protected function registerManager(): void
    {
        $this->app->singleton(
            ImpersonationManager::class,
            static fn (Application $app): ImpersonationManager => new ImpersonationManager(
                app: $app,
                config: $app->make(Config::class),
                modeRegistry: $app->make(ModeRegistry::class),
                identities: $app->make(IdentityResolver::class),
            ),
        );

        $this->app->alias(ImpersonationManager::class, 'impersonator');
    }

    /**
     * Registered as factories rather than eagerly constructed, so an installation
     * configured to one driver never builds the others.
     */
    protected function registerDriversAndAdapters(): void
    {
        $manager = $this->app->make(ImpersonationManager::class);

        $manager->extendAdapter('session', static fn (Container $app): AuthAdapter => new SessionGuardAdapter(
            auth: $app->make(AuthFactory::class),
            session: $app->make(Session::class),
            config: $app->make(Config::class),
            identities: $app->make(IdentityResolver::class),
            terminator: $app->make(SessionTerminator::class),
        ));

        // The API adapters, each registered unconditionally but reporting `isAvailable()`
        // false when its package is absent. Registering rather than conditionally skipping
        // is what makes a misconfiguration fail loudly at selection — "adapter [sanctum] is
        // not available, install laravel/sanctum" — instead of mysteriously at use.
        $manager->extendAdapter('sanctum', static fn (Container $app): AuthAdapter => new SanctumTokenAdapter(
            identities: $app->make(IdentityResolver::class),
            settings: $app->make(Settings::class),
        ));

        $manager->extendAdapter('passport', static fn (Container $app): AuthAdapter => new PassportAdapter(
            identities: $app->make(IdentityResolver::class),
            settings: $app->make(Settings::class),
        ));

        $manager->extendAdapter('jwt', static fn (Container $app): AuthAdapter => new JwtAdapter(
            app: $app,
            identities: $app->make(IdentityResolver::class),
            settings: $app->make(Settings::class),
        ));

        $manager->extend('session', static fn (Container $app): ImpersonationDriver => new SessionDriver(
            audits: $app->make(AuditStore::class),
            adapter: $app->make(ImpersonationManager::class)->adapter(),
            state: $app->make(SessionState::class),
            settings: $app->make(Settings::class),
            events: $app->make(Dispatcher::class),
            clock: $app->make(ClockInterface::class),
        ));

        // Registered unconditionally, and reporting `isAvailable()` false when stancl is
        // absent — so `driver => tenancy` on an installation without it fails with "not
        // available in this installation" rather than a class-not-found deep in a request.
        $manager->extend('tenancy', static fn (Container $app): ImpersonationDriver => new TenancyDriver(
            audits: $app->make(AuditStore::class),
            adapter: $app->make(ImpersonationManager::class)->adapter(),
            tokens: $app->make(TokenRepository::class),
            policy: $app->make(AuthorizationPolicy::class),
            urls: $app->make(AcceptUrlBuilder::class),
            state: $app->make(SessionState::class),
            settings: $app->make(Settings::class),
            events: $app->make(Dispatcher::class),
            clock: $app->make(ClockInterface::class),
        ));

        $manager->extend('token', static fn (Container $app): ImpersonationDriver => new TokenDriver(
            audits: $app->make(AuditStore::class),
            adapter: $app->make(ImpersonationManager::class)->adapter(),
            tokens: $app->make(TokenRepository::class),
            policy: $app->make(AuthorizationPolicy::class),
            urls: $app->make(AcceptUrlBuilder::class),
            state: $app->make(SessionState::class),
            settings: $app->make(Settings::class),
            events: $app->make(Dispatcher::class),
            clock: $app->make(ClockInterface::class),
        ));
    }

    // ── Wiring ──────────────────────────────────────────────────────────────

    protected function registerRoutes(): void
    {
        $settings = $this->app->make(Settings::class);

        if ($settings->bool('routes.register', true)) {
            $this->loadRoutesFrom($this->packagePath('routes/impersonator.php'));
        }

        // Off by default. An impersonation API is a remote-control surface for every account in the
        // system, so it is something an operator switches on deliberately rather than something they
        // acquire by upgrading a package.
        if ($settings->bool('api.enabled', false)) {
            $this->loadRoutesFrom($this->packagePath('routes/api.php'));
        }
    }

    protected function registerViews(): void
    {
        $this->loadViewsFrom($this->packagePath('resources/views'), 'impersonator');
    }

    /**
     * The Blade surface.
     *
     * `@impersonating` reads server-side state, never request input — the whole
     * reason a template can be trusted to reveal an impersonation is that a client
     * cannot make the directive lie.
     */
    protected function registerBladeDirectives(): void
    {
        Blade::if('impersonating', static fn (): bool => app(ImpersonationManager::class)->isImpersonating());

        Blade::if(
            'impersonationMode',
            static fn (string $mode): bool => app(ImpersonationManager::class)->mode()?->is($mode) === true,
        );

        // Runs the same policy the action runs, so a hidden button and a 403 can
        // never disagree.
        Blade::if('canImpersonate', static fn (mixed $target = null): bool => ($target instanceof Authenticatable
            || $target instanceof Model)
            && app(ImpersonationManager::class)->canImpersonate($target)->allowed);

        Blade::directive(
            'impersonationBanner',
            static fn (): string => "<?php echo app('" . BannerPresenter::class . "')->render(); ?>",
        );
    }

    /**
     * `Route::impersonate()` — the one-line route registration, for parity with the
     * ecosystem's established shape.
     */
    protected function registerRouteMacro(): void
    {
        if (Route::hasMacro('impersonate')) {
            return;
        }

        Route::macro('impersonate', static function (): void {
            // Registered through the facade rather than the macro's bound `$this`.
            // Both reach the same router, and group state lives on the router — so
            // a call inside a Route::group() still inherits that group's prefix and
            // middleware, without a docblock asserting a type the analyser cannot
            // otherwise see.
            $settings = app(Settings::class);

            Route::get($settings->string('routes.leave_path', 'leave'), LeaveImpersonationController::class)
                ->name($settings->string('routes.name_prefix', 'impersonator.') . 'leave');
        });
    }

    protected function registerEventListeners(): void
    {
        $events = $this->app->make(Dispatcher::class);

        $events->listen(ImpersonationStarted::class, [LogImpersonationLifecycle::class, 'handleStarted']);
        $events->listen(ImpersonationEnded::class, [LogImpersonationLifecycle::class, 'handleEnded']);
        $events->listen(ImpersonationRejected::class, [LogImpersonationLifecycle::class, 'handleRejected']);

        // Notifications are a listener rather than a step inside the actions: whether to
        // tell anybody is an application policy, and a host can unsubscribe this and
        // substitute its own without touching the lifecycle.
        $events->listen(ImpersonationStarted::class, [SendImpersonationNotifications::class, 'handleStarted']);
        $events->listen(ImpersonationRevoked::class, [SendImpersonationNotifications::class, 'handleRevoked']);
        $events->listen(ImpersonationExpired::class, [SendImpersonationNotifications::class, 'handleExpired']);

        // Break-glass. Approvers have to be *told* a request is waiting: a queue nobody is
        // notified about is one that gets checked after the incident is over, at which point
        // the operator has already asked a colleague to work around the control.
        $events->listen(ApprovalRequested::class, [SendImpersonationNotifications::class, 'handleApprovalRequested']);
        $events->listen(ApprovalGranted::class, [SendImpersonationNotifications::class, 'handleApprovalGranted']);
        $events->listen(ApprovalDenied::class, [SendImpersonationNotifications::class, 'handleApprovalDenied']);
    }

    /**
     * The drop-in component surface.
     *
     * Registered by class rather than as an anonymous namespace so each component can
     * decide to render nothing — which is the property that lets a host application
     * place `<x-impersonation-banner />` once in a layout and never wrap it in a
     * conditional. A forgotten conditional is a banner that silently fails to appear.
     */
    protected function registerBladeComponents(): void
    {
        Blade::component('impersonation-banner', ImpersonationBanner::class);
        Blade::component('impersonate-button', ImpersonateButton::class);
        Blade::component('impersonation-leave-button', LeaveImpersonationButton::class);
        Blade::component('impersonation-badge', ImpersonationBadge::class);
        Blade::component('when-impersonating', WhenImpersonating::class);

        // Also exposed under a namespace, so `<x-impersonator::banner />` works for
        // teams that prefer namespaced components or already own these short names.
        Blade::componentNamespace('Simtabi\\Laranail\\Impersonator\\Laravel\\View\\Components', 'impersonator');
    }

    /**
     * Enforcement middleware.
     *
     * Aliased *and* optionally appended to the application's own groups: registering
     * them only on the package's routes would enforce nothing, since the requests that
     * need constraining are the host application's.
     */
    protected function registerMiddleware(): void
    {
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('impersonator.lifetime', GuardImpersonationLifetime::class);
        $router->aliasMiddleware('impersonator.mode', EnforceImpersonationMode::class);
        $router->aliasMiddleware('impersonator.trail', RecordImpersonationTrail::class);

        $settings = $this->app->make(Settings::class);

        foreach ($settings->stringList('routes.auto_append_to_groups') as $group) {
            foreach ($settings->stringList('routes.enforcement') as $middleware) {
                // Appended, so it runs after the host's own session and auth
                // middleware — reading impersonation state requires a started session.
                $router->pushMiddlewareToGroup($group, $middleware);
            }
        }
    }

    /**
     * Gates, every one delegating to the single AuthorizationPolicy.
     *
     * Defined only when the application has not already defined them, so an app that
     * wants its own `impersonate` ability keeps it. Delegating rather than
     * reimplementing is the point: a gate that decided independently would be a second
     * set of rules to keep in sync, and the one that drifts is always the copy.
     */
    protected function registerGates(): void
    {
        $gate = $this->app->make(Gate::class);
        $this->app->make(Settings::class);

        $abilities = [
            'impersonator.revoke' => static fn (Authenticatable|Model $user, string $auditId): bool => app(
                AuthorizationPolicy::class,
            )->authorizeRevoke(app(IdentityResolver::class)->fromUser($user), $auditId)->allowed,

            'impersonator.audit.view' => static fn (Authenticatable|Model $user): bool => app(
                AuthorizationPolicy::class,
            )->authorizeAuditAccess(app(IdentityResolver::class)->fromUser($user))->allowed,

            'impersonator.mode' => static fn (Authenticatable|Model $user, string $mode): bool => app(
                AuthorizationPolicy::class,
            )->authorizeMode(app(IdentityResolver::class)->fromUser($user), $mode)->allowed,
        ];

        foreach ($abilities as $ability => $callback) {
            if (! $gate->has($ability)) {
                $gate->define($ability, $callback);
            }
        }

        // The audit model's policy, so `$user->can('view', $audit)` and Blade's `@can` cover an
        // audit UI.
        //
        // Registered unconditionally rather than after a `getPolicyFor()` check, and that matters
        // for a non-obvious reason: `getPolicyFor()` *instantiates* the policy to answer, which
        // would resolve the session store during boot — freezing the session driver before an
        // application (or a test) had a chance to configure it. Overwriting is safe anyway, since
        // application providers boot after package ones, so an app registering its own still wins.
        $gate->policy(ImpersonationAudit::class, ImpersonationAuditPolicy::class);

        // The target-scoped `impersonate` ability is deliberately NOT defined here.
        // It is the application's override point, and the policy consults it only when
        // the application has defined one — so defining ours would be circular: the
        // gate would call the policy, which would consult the gate, forever.
    }

    /**
     * The named limiters the routes reference.
     *
     * Enter is keyed by the operator, not the IP: the risk being limited is one
     * authorized person enumerating accounts, and they will do it from one address.
     */
    protected function registerRateLimiters(): void
    {
        $settings = $this->app->make(Settings::class);

        RateLimiter::for('impersonator-enter', static function (Request $request) use ($settings): Limit {
            $identifier = $request->user()?->getAuthIdentifier();
            $key = is_scalar($identifier) ? (string) $identifier : ($request->ip() ?? 'unknown');

            return Limit::perMinutes(
                max(1, (int) ceil($settings->int('rate_limiting.enter.decay', 60) / 60)),
                $settings->int('rate_limiting.enter.attempts', 5),
            )->by('impersonator-enter:' . $key);
        });

        RateLimiter::for('impersonator-api', static function (Request $request) use ($settings): Limit {
            $identifier = $request->user()?->getAuthIdentifier();

            return Limit::perMinutes(
                max(1, (int) ceil($settings->int('rate_limiting.api.decay', 60) / 60)),
                $settings->int('rate_limiting.api.attempts', 30),
            )->by('impersonator-api:' . (is_scalar($identifier) ? (string) $identifier : ($request->ip() ?? 'unknown')));
        });

        RateLimiter::for('impersonator-accept', static fn (Request $request): Limit => Limit::perMinutes(
            max(1, (int) ceil($settings->int('rate_limiting.accept.decay', 60) / 60)),
            $settings->int('rate_limiting.accept.attempts', 10),
        )->by('impersonator-accept:' . ($request->ip() ?? 'unknown')));
    }

    /**
     * Render the package's refusals as the status codes they are.
     *
     * Registered in the bridge rather than by implementing Symfony's
     * HttpExceptionInterface on the exceptions, because those live in the Core layer,
     * which may not import a framework. Mapping here keeps that boundary intact.
     *
     * Only the safe, operator-facing message is rendered. No internal detail reaches a
     * user-facing response — the diagnosable version went to the log and the
     * rejection event.
     */
    protected function registerExceptionRendering(): void
    {
        $handler = $this->app->make(ExceptionHandler::class);

        // `renderable` is the Laravel handler's registration hook; a host application
        // that swapped in its own handler simply keeps its own rendering.
        if (! method_exists($handler, 'renderable')) {
            return;
        }

        $handler->renderable(static fn (ImpersonationDenied $e, Request $request) => $request->expectsJson()
            ? response()->json(['message' => $e->getMessage(), 'reason' => $e->code()], 403)
            : response($e->getMessage(), 403));

        $handler->renderable(static fn (ConcurrencyLimitReached $e, Request $request) => $request->expectsJson()
            ? response()->json(['message' => $e->getMessage(), 'reason' => $e->decision->code], 429)
            : response($e->getMessage(), 429));

        $handler->renderable(
            // Deliberately uniform: telling a caller whether a token merely expired
            // tells them the token was real.
            static fn (TokenRejected $e, Request $request) => $request->expectsJson()
            ? response()->json(['message' => $e->getMessage()], 403)
            : response($e->getMessage(), 403));

        // 202, not 403. The operator holds every permission the request needed, nothing was
        // refused, and something was created — a pending request. Rendering this as a refusal
        // would send an operator asking for permissions they already have.
        $handler->renderable(static fn (ApprovalRequired $e, Request $request) => $request->expectsJson()
            ? response()->json([
                'message' => $e->getMessage(),
                'reason' => $e->code(),
                'approval' => [
                    'id' => $e->approvalId,
                    'expires_at' => $e->expiresAt->format(DATE_ATOM),
                ],
            ], 202)
            : response($e->getMessage(), 202));

        // 409: the request itself was fine, but the row is not in a state that can be decided —
        // somebody else answered it first, or it expired while the approver was reading it.
        $handler->renderable(static fn (ApprovalNotDecidable $e, Request $request) => $request->expectsJson()
            ? response()->json(['message' => $e->getMessage(), 'reason' => $e->reason()], 409)
            : response($e->getMessage(), 409));
    }

    protected function registerCommands(): void
    {
        $this->commands([
            DoctorCommand::class,
            EnterCommand::class,
            ExportAuditCommand::class,
            PruneApprovalsCommand::class,
            PruneTokensCommand::class,
            VerifyAuditCommand::class,
        ]);
    }

    /**
     * The `php artisan about` panel.
     *
     * Reports the four facts that change what impersonation *does* and are otherwise only
     * discoverable by reading config: which driver and adapter are active, whether the API is
     * exposed, and whether approval and tamper evidence are on. Each value is deferred so a
     * closure runs only when `about` is actually invoked.
     *
     * Never reports the audit hash key, the security webhook, or anything else that would turn a
     * pasted `about` output — which is what people attach to a bug report — into a leak.
     */
    protected function registerAboutCommand(): void
    {
        if (! class_exists(AboutCommand::class)) {
            return;
        }

        $settings = $this->app->make(Settings::class);

        AboutCommand::add('Impersonator', fn (): array => [
            'Enabled' => $settings->bool('enabled', true) ? 'yes' : 'NO',
            'Driver' => $settings->string('driver', 'session'),
            'Adapter' => $settings->string('adapter', 'session'),
            'Default mode' => $settings->string('default_mode', 'full'),
            'Max duration' => ($max = $settings->positiveIntOrNull('limits.max_duration')) === null
                ? 'unlimited'
                : $max . ' min',
            'Approval required' => $settings->bool('approval.require', false) ? 'yes' : 'no',
            'Tamper evidence' => $settings->bool('audit.tamper_evident', false) ? 'on' : 'off',
            'REST API' => $settings->bool('api.enabled', false) ? 'ENABLED' : 'disabled',
        ]);
    }

    protected function registerPublishing(): void
    {
        $this->publishes([
            $this->configPath() => $this->app->configPath('impersonator.php'),
        ], 'impersonator-config');

        $this->publishes([
            $this->packagePath('resources/views') => $this->app->resourcePath('views/vendor/impersonator'),
        ], 'impersonator-views');

        $this->publishes([
            $this->packagePath('database/migrations/create_impersonator_tables.php.stub') => $this->app
                ->databasePath('migrations/' . date('Y_m_d_His') . '_create_impersonator_tables.php'),
        ], 'impersonator-migrations');
    }

    protected function configPath(): string
    {
        return $this->packagePath('config/impersonator.php');
    }

    protected function packagePath(string $relative): string
    {
        return dirname(__DIR__, 3) . '/' . $relative;
    }
}
