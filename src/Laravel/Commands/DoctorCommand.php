<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Database\Schema\Builder as SchemaBuilder;
use Illuminate\Session\SessionManager;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Schema;
use SessionHandlerInterface;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Impersonator\Core\Support\FailureReport;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Commands\Concerns\SupportsNamespacedNames;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Throwable;

/**
 * Checks the things that are wrong silently.
 *
 * Every check here exists because the failure it catches produces no error — impersonation
 * appears to work, and the gap only surfaces during an incident or an audit. A missing table
 * throws on first use and needs no doctor; an operator who can enter but not choose a mode, or
 * a revocation switch that cannot actually end a session, will pass every smoke test.
 *
 * Three severities, and the distinction is what makes the output worth reading:
 *
 *  - **fail** — impersonation is broken or a control is not enforcing. Exits non-zero.
 *  - **warn** — it works, but a control is weaker than the configuration implies.
 *  - **ok** — checked and sound.
 *
 * Exits non-zero only on a failure, so it can run in CI as a gate rather than as advice.
 */
class DoctorCommand extends Command
{
    use SupportsNamespacedNames;

    protected $description = 'Diagnose the impersonation configuration and report what is silently wrong';

    /** @var list<array{status: string, check: string, detail: string}> */
    private array $results = [];

    protected function namespacedSignature(): string
    {
        return 'laranail::impersonator.doctor';
    }

    /**
     * Nothing the container might refuse to build is injected here.
     *
     * The manager and the policy are resolved inside, guarded, because both reach the audit store —
     * and the audit store throws outright when tamper evidence is on without a key. Injecting them
     * would make the doctor crash with a stack trace on exactly the misconfigured install somebody
     * is running it to diagnose, which is the one case it has to handle well.
     */
    public function handle(Settings $settings, FailureReport $health, Gate $gate): int
    {
        $this->components->info('Impersonator diagnostics');

        $this->checkEnabled($settings);
        $this->checkBootHealth($health);
        $this->checkTamperEvidence($settings);
        $this->checkTables($settings);

        $manager = $this->resolve(ImpersonationManager::class);
        $policy = $this->resolve(AuthorizationPolicy::class);

        if ($manager instanceof ImpersonationManager) {
            $this->checkTargets($manager, $settings);
            $this->checkGuards($manager, $settings);
            $this->checkDriverAndAdapter($manager, $settings);
        }

        if ($policy instanceof AuthorizationPolicy) {
            $this->checkModePermissionTrap($settings, $policy);
        }

        $this->checkGate($settings, $gate);
        $this->checkSessionTermination($settings);
        $this->checkDuration($settings);
        $this->checkApproval($settings);
        $this->checkApi($settings);
        $this->checkConflictingPackages($settings);

        return $this->render();
    }

    /**
     * Build one service, turning a container failure into a diagnosis.
     *
     * @param class-string $service
     */
    private function resolve(string $service): ?object
    {
        try {
            $instance = $this->laravel->make($service);
        } catch (Throwable $e) {
            $this->recordFail('Container', sprintf(
                '[%s] could not be built, so the checks that need it were skipped: %s',
                $service,
                $e->getMessage(),
            ));

            return null;
        }

        return is_object($instance) ? $instance : null;
    }

    // ── checks ──────────────────────────────────────────────────────────────

    private function checkEnabled(Settings $settings): void
    {
        $settings->bool('enabled', true)
            ? $this->recordOk('Master switch', 'Impersonation is enabled.')
            : $this->recordWarn(
                'Master switch',
                'impersonator.enabled is false, so every enter is refused. Revocation still works, '
                . 'which is deliberate: turning the feature off during an incident must not also '
                . 'remove the ability to kill the sessions already running.',
            );
    }

    /**
     * Anything that degraded during boot.
     *
     * The most valuable check in the command. A degradable boot operation that failed — routes not
     * registered, a Blade component missing, listeners not attached — leaves an application that
     * starts cleanly and quietly lacks a feature.
     */
    private function checkBootHealth(FailureReport $health): void
    {
        if ($health->isHealthy()) {
            $this->recordOk('Boot health', 'Every registration completed.');

            return;
        }

        foreach ($health->degraded() as $operation => $failure) {
            $this->recordFail('Boot health', sprintf('%s degraded: %s (%s)', $operation, $failure['message'], $failure['type']));
        }
    }

    private function checkTables(Settings $settings): void
    {
        $connection = $settings->nullableString('audit.connection');

        try {
            $schema = $connection === null ? Schema::connection(null) : Schema::connection($connection);
        } catch (Throwable $e) {
            $this->recordFail('Tables', sprintf('The audit connection [%s] is unreachable: %s', $connection ?? 'default', $e->getMessage()));

            return;
        }

        $tables = [
            'audit.table' => 'impersonator_audits',
            'trail.table' => 'impersonator_audit_events',
            'tokens.table' => 'impersonator_tokens',
            'approval.table' => 'impersonator_approval_requests',
        ];

        $missing = [];

        foreach ($tables as $key => $default) {
            $table = $settings->string($key, $default);

            if (! $this->tableExists($schema, $table)) {
                $missing[] = $table;
            }
        }

        $missing === []
            ? $this->recordOk('Tables', 'All four tables exist.')
            : $this->recordFail(
                'Tables',
                sprintf(
                    'Missing: %s. Publish and run the migration: php artisan vendor:publish '
                    . '--tag=impersonator-migrations && php artisan migrate',
                    implode(', ', $missing),
                ),
            );
    }

    private function tableExists(SchemaBuilder $schema, string $table): bool
    {
        try {
            return $schema->hasTable($table);
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * The target allowlist, checked against what actually resolved.
     *
     * This compares the raw config to the registry rather than iterating the registry, because the
     * registry **silently drops** any entry that is not an installed Eloquent model — a typo or a
     * renamed class narrows the allowlist instead of raising anything. Iterating the resolved types
     * would therefore never see the problem: the broken entry is precisely the one that is missing.
     *
     * An empty allowlist is a failure rather than a warning. It is not a permissive default; it
     * refuses every impersonation, with a message about the target type that reads like a bug in
     * the caller.
     */
    private function checkTargets(ImpersonationManager $manager, Settings $settings): void
    {
        $types = $manager->targets()->all();
        $configured = $settings->array('targets.allowlist');

        $dropped = [];

        foreach ($configured as $alias => $entry) {
            $model = is_array($entry) ? ($entry['model'] ?? null) : $entry;
            $key = is_string($alias) ? $alias : (is_string($model) ? $model : 'unknown');

            if (! array_key_exists($key, $types)) {
                $dropped[] = sprintf('%s => %s', $key, is_string($model) ? $model : get_debug_type($model));
            }
        }

        if ($dropped !== []) {
            $this->recordFail('Targets', sprintf(
                'Dropped from the allowlist because they are not installed Eloquent models: %s. '
                . 'These were silently ignored, so an enter against them is refused as a '
                . 'non-allowlisted target.',
                implode(', ', $dropped),
            ));

            return;
        }

        $types === []
            ? $this->recordFail(
                'Targets',
                'impersonator.targets.allowlist is empty, so every enter is refused as a '
                . 'non-allowlisted target. Add at least one model.',
            )
            : $this->recordOk('Targets', sprintf(
                '%d impersonatable type(s): %s.',
                count($types),
                implode(', ', array_keys($types)),
            ));
    }

    private function checkGuards(ImpersonationManager $manager, Settings $settings): void
    {
        $configured = [
            $settings->string('guards.impersonator', 'web'),
            $settings->string('guards.target', 'web'),
        ];

        foreach ($manager->targets()->all() as $type) {
            $guard = $type->guard;

            if (is_string($guard) && $guard !== '') {
                $configured[] = $guard;
            }
        }

        $unknown = [];

        foreach (array_unique($configured) as $guard) {
            if (! is_array(config('auth.guards.' . $guard))) {
                $unknown[] = $guard;
            }
        }

        $unknown === []
            ? $this->recordOk('Guards', sprintf('All configured guards exist: %s.', implode(', ', array_unique($configured))))
            : $this->recordFail(
                'Guards',
                sprintf('Guards not defined in config/auth.php: %s.', implode(', ', $unknown)),
            );
    }

    private function checkDriverAndAdapter(ImpersonationManager $manager, Settings $settings): void
    {
        $driver = $settings->string('driver', 'session');
        $adapter = $settings->string('adapter', 'session');

        try {
            $manager->driver($driver);
            $this->recordOk('Driver', sprintf('[%s] resolves.', $driver));
        } catch (Throwable $e) {
            $this->recordFail('Driver', sprintf('[%s] does not resolve: %s', $driver, $e->getMessage()));
        }

        try {
            $manager->adapter($adapter);
            $this->recordOk('Adapter', sprintf('[%s] resolves.', $adapter));
        } catch (Throwable $e) {
            $this->recordFail('Adapter', sprintf('[%s] does not resolve: %s', $adapter, $e->getMessage()));
        }

        // The token driver is useless without somewhere to send the operator.
        if ($driver === 'token' && $settings->nullableString('urls.base_domain') === null) {
            $this->recordWarn(
                'Handoff URLs',
                'The token driver is selected but impersonator.urls.base_domain is unset, so accept '
                . 'URLs are built against the current host. For a cross-domain handoff — the reason '
                . 'to pick this driver — that is the wrong host.',
            );
        }
    }

    /**
     * The trap: an operator holding `impersonator.enter` and no mode permission.
     *
     * Both are required, so such an operator can impersonate nothing at all while appearing fully
     * configured. The error they get names the *mode*, which sends them asking for the wrong
     * permission — and this is the single most common way an install is quietly broken.
     *
     * Keyed on the **active policy** rather than on whether an RBAC package is installed. Those are
     * not the same question: the policy is what actually decides, it can be set explicitly in
     * config, and an install that names `RbacPolicy` without spatie present still enforces per-mode
     * permissions. Checking for the package would tell that install any mode is allowed.
     */
    private function checkModePermissionTrap(Settings $settings, AuthorizationPolicy $policy): void
    {
        if (! $policy instanceof RbacPolicy) {
            $this->recordOk('Mode permissions', sprintf(
                'The active policy is [%s], which does not check per-mode permissions, so any '
                . 'registered mode may be used.',
                $policy::class,
            ));

            return;
        }

        $template = $settings->string('authorization.permissions.mode', 'impersonator.mode.%s');
        $enter = $settings->string('authorization.permissions.enter', 'impersonator.enter');
        $default = $settings->string('default_mode', 'full');

        $this->recordWarn(
            'Mode permissions',
            sprintf(
                'Entering needs BOTH [%s] and the per-mode permission — for the default mode that is '
                . '[%s]. Granting only the first produces an operator who can impersonate nothing '
                . 'while looking correctly configured. Verify your seeder grants both.',
                $enter,
                sprintf($template, $default),
            ),
        );
    }

    private function checkGate(Settings $settings, Gate $gate): void
    {
        $ability = $settings->nullableString('authorization.gate_ability');

        if ($ability === null) {
            $this->recordOk('Gate', 'No gate ability configured.');

            return;
        }

        $gate->has($ability)
            ? $this->recordOk('Gate', sprintf('The [%s] ability is defined and will be consulted.', $ability))
            : $this->recordWarn(
                'Gate',
                sprintf(
                    'impersonator.authorization.gate_ability is [%s] but no such ability is defined, '
                    . 'so it is skipped. That is deliberate — an undefined ability denies everything '
                    . 'in Laravel, and treating "not defined" as "denied" would break every install '
                    . 'that never opted in — but if you meant to define it, it is not being enforced.',
                    $ability,
                ),
            );
    }

    /**
     * Whether a revocation can actually end a session, or only record the intent.
     *
     * The difference matters operationally. With a server-side session store the kill switch is
     * immediate; with `cookie` or `array` there is nothing to destroy from outside, so the session
     * ends on its next request — which for an idle tab could be a long time.
     */
    private function checkSessionTermination(Settings $settings): void
    {
        $driver = config('session.driver');
        $driver = is_string($driver) ? $driver : 'unknown';

        if (! $settings->bool('session.destroy_on_revoke', true)) {
            $this->recordWarn(
                'Session termination',
                'impersonator.session.destroy_on_revoke is off, so a revocation is only recorded. '
                . 'The impersonated session ends on its next request, which for an idle tab may be a while.',
            );

            return;
        }

        if (in_array($driver, ['cookie', 'array'], true)) {
            $this->recordWarn(
                'Session termination',
                sprintf(
                    'The [%s] session driver keeps no server-side record, so a revocation cannot be '
                    . 'enforced out of band — it is recorded and the middleware ends the session on its '
                    . 'next request. Use database, redis or file for an immediate kill switch.',
                    $driver,
                ),
            );

            return;
        }

        try {
            $store = $this->laravel->make(SessionManager::class)->driver();
            $handler = $store instanceof Store ? $store->getHandler() : null;
        } catch (Throwable $e) {
            $this->recordWarn('Session termination', sprintf('The session store could not be inspected: %s', $e->getMessage()));

            return;
        }

        $handler instanceof SessionHandlerInterface
            ? $this->recordOk('Session termination', sprintf('The [%s] driver can be destroyed out of band; revocation is immediate.', $driver))
            : $this->recordWarn('Session termination', sprintf('The [%s] driver exposes no destroyable handler.', $driver));
    }

    private function checkDuration(Settings $settings): void
    {
        $max = $settings->positiveIntOrNull('limits.max_duration');

        $max === null
            ? $this->recordWarn(
                'Maximum duration',
                'impersonator.limits.max_duration is unlimited, so an impersonation left open stays '
                . 'open. An abandoned session inside a customer account is the one that shows up in '
                . 'an audit with no explanation.',
            )
            : $this->recordOk('Maximum duration', sprintf('Impersonations are force-ended after %d minute(s).', $max));
    }

    private function checkTamperEvidence(Settings $settings): void
    {
        if (! $settings->bool('audit.tamper_evident', false)) {
            $this->recordWarn(
                'Tamper evidence',
                'The audit chain is off, so a row that is altered or deleted leaves no trace. Set '
                . 'impersonator.audit.tamper_evident and a hash_key if the trail is evidence.',
            );

            return;
        }

        $key = $settings->nullableString('audit.hash_key');

        if ($key === null) {
            // Checked before anything resolves the audit store, which throws on this exact state.
            // An application in this condition boots cleanly and fails on its first impersonation,
            // so the doctor is the only thing that will tell you before a user does.
            $this->recordFail(
                'Tamper evidence',
                'Enabled but impersonator.audit.hash_key is unset. Every impersonation will fail '
                . 'when the audit store is built. Set a long random key kept outside the database.',
            );

            return;
        }

        strlen($key) < 32
            ? $this->recordWarn('Tamper evidence', sprintf('The hash key is %d bytes. Use at least 32.', strlen($key)))
            : $this->recordOk('Tamper evidence', 'Enabled with a key of adequate length.');
    }

    private function checkApproval(Settings $settings): void
    {
        if (! $settings->bool('approval.require', false)) {
            $this->recordOk('Break-glass approval', 'Not required.');

            return;
        }

        $exempt = $settings->stringList('approval.except_modes');

        $this->recordOk('Break-glass approval', sprintf(
            'Required for every mode except: %s. Requests expire after %d minute(s).',
            $exempt === [] ? 'none' : implode(', ', $exempt),
            $settings->int('approval.ttl', 15),
        ));

        if (! $settings->bool('notifications.approvals.enabled', false)) {
            $this->recordWarn(
                'Break-glass approval',
                'Approval is required but approver notifications are off '
                . '(impersonator.notifications.approvals.enabled). A queue nobody is told about gets '
                . 'checked after the incident, by which point the operator has asked a colleague to '
                . 'work around the control.',
            );
        }

        if (! $this->scheduledPruneLikely()) {
            $this->recordWarn(
                'Break-glass approval',
                'Schedule laranail::impersonator.prune-approvals, or an operator whose request went '
                . 'unanswered is never told that nobody replied.',
            );
        }
    }

    private function checkApi(Settings $settings): void
    {
        if (! $settings->bool('api.enabled', false)) {
            $this->recordOk('REST API', 'Disabled, which is the default.');

            return;
        }

        $middleware = $settings->stringList('api.middleware');

        $hasAuth = array_filter($middleware, static fn (string $m): bool => str_starts_with($m, 'auth'));

        $hasAuth === []
            ? $this->recordFail(
                'REST API',
                sprintf(
                    'The API is enabled but its middleware [%s] contains no auth guard. That is an '
                    . 'unauthenticated remote-control surface for every account in the system.',
                    implode(', ', $middleware),
                ),
            )
            : $this->recordOk('REST API', sprintf('Enabled behind [%s].', implode(', ', $middleware)));
    }

    /**
     * Other impersonation packages in the same application.
     *
     * Not a failure — two packages can coexist. But both will register routes, both may write
     * session keys, and a leave through one will not end an impersonation started by the other,
     * which produces an audit trail that disagrees with itself.
     *
     * The list comes from config rather than a constant so an application can add whatever else it
     * knows conflicts — a Filament plugin, an internal package — without waiting on this one.
     */
    private function checkConflictingPackages(Settings $settings): void
    {
        $found = [];

        foreach ($settings->array('doctor.conflicting_packages') as $class => $package) {
            if (is_string($class) && $class !== '' && class_exists($class)) {
                $found[] = is_string($package) ? $package : $class;
            }
        }

        $found === []
            ? $this->recordOk('Conflicting packages', 'No other impersonation package detected.')
            : $this->recordWarn(
                'Conflicting packages',
                sprintf(
                    'Also installed: %s. Two impersonation packages both register routes and session '
                    . 'state, and leaving through one does not end an impersonation started by the '
                    . 'other — which produces an audit trail that disagrees with itself.',
                    implode(', ', $found),
                ),
            );
    }

    /**
     * A weak check on purpose.
     *
     * The scheduler is defined in the application's own bootstrap and there is no reliable way to
     * ask "is this command scheduled". Reporting a warning that a host may safely ignore beats
     * silently assuming the sweep runs.
     */
    private function scheduledPruneLikely(): bool
    {
        return false;
    }

    // ── output ──────────────────────────────────────────────────────────────

    private function recordOk(string $check, string $detail): void
    {
        $this->results[] = ['status' => 'ok', 'check' => $check, 'detail' => $detail];
    }

    private function recordWarn(string $check, string $detail): void
    {
        $this->results[] = ['status' => 'warn', 'check' => $check, 'detail' => $detail];
    }

    private function recordFail(string $check, string $detail): void
    {
        $this->results[] = ['status' => 'fail', 'check' => $check, 'detail' => $detail];
    }

    private function render(): int
    {
        $failures = 0;
        $warnings = 0;

        foreach ($this->results as $result) {
            $label = match ($result['status']) {
                'fail' => '<fg=red>FAIL</>',
                'warn' => '<fg=yellow>WARN</>',
                default => '<fg=green>OK</>',
            };

            $this->components->twoColumnDetail(sprintf('%s  %s', $label, $result['check']), '');
            $this->line('       ' . $result['detail']);

            $result['status'] === 'fail' && $failures++;
            $result['status'] === 'warn' && $warnings++;
        }

        $this->newLine();

        if ($failures > 0) {
            $this->components->error(sprintf(
                '%d check(s) failed, %d warning(s). Impersonation is broken or a control is not enforcing.',
                $failures,
                $warnings,
            ));

            return self::FAILURE;
        }

        // Warnings do not fail the command. Several are legitimate choices — an unlimited duration
        // on an internal tool, tamper evidence off where the trail is not evidence — and a doctor
        // that exits non-zero for a deliberate decision is one teams stop running.
        $warnings > 0
            ? $this->components->warn(sprintf('No failures, %d warning(s) worth reading.', $warnings))
            : $this->components->info('Everything checks out.');

        return self::SUCCESS;
    }
}
