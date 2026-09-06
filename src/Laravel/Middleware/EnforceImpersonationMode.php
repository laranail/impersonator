<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Contracts\Events\Dispatcher;
use Symfony\Component\HttpFoundation\Response;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Simtabi\Laranail\Impersonator\Core\Support\ModeRegistry;
use Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\LivewireAction;
use Simtabi\Laranail\Impersonator\Core\Events\ModeViolationBlocked;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Support\PersistenceGuard;

/**
 * Applies the active mode to the current request.
 *
 * The mode is read from server-side state, never from the request, which is what
 * makes it untamperable: there is no header, parameter or cookie a client can set to
 * widen its own envelope, and the only route to a different mode is leaving and
 * re-entering, which mints a fresh audit row.
 *
 * When the mode asks for it, a persistence-level guard is installed for the
 * remainder of the request. That uses `DB::beforeExecuting` rather than Eloquent's
 * saving/deleting events, because model events see neither query-builder writes
 * (`DB::table(...)->update()`) nor raw statements — and a read-only mode with a hole
 * that size is not read-only. The trade-off is stated on `installPersistenceGuard`.
 */
final readonly class EnforceImpersonationMode
{
    public function __construct(
        private ImpersonationManager $impersonator,
        private ModeRegistry $modes,
        private Dispatcher $events,
        private PersistenceGuard $guard,
        private Settings $settings,
    ) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        $session = $this->impersonator->current();

        if ($session === null) {
            return $next($request);
        }

        $enforcer = $this->modes->enforcer($session->mode);

        $decision = $enforcer->check($this->actionFor($request), $session);

        if ($decision->denied()) {
            $this->refuse($session, $request, $decision);
        }

        if (! $enforcer->guardsPersistence()) {
            return $next($request);
        }

        // Armed for this request only, and disarmed in `finally` so an exception cannot leave the
        // guard listening. It has to come off: closing an impersonation is an UPDATE on the audit
        // row, and a read-only guard still armed would deny it and trap the operator inside the
        // account. See PersistenceGuard for the rest of why.
        $this->guard->arm($session, $enforcer, $request->path(), $this->exemptTables());

        try {
            return $next($request);
        } finally {
            $this->guard->disarm();
        }
    }

    /**
     * Tables the persistence guard never judges.
     *
     * Two groups, for two different reasons.
     *
     * The package's own tables are exempt because they are its bookkeeping, not the impersonated
     * user's actions: the audit row, its trail, handoff tokens and approvals all get written *while*
     * an impersonation is in flight, and a mode that blocked them would prevent the very record
     * that makes the mode auditable.
     *
     * Laravel's session and cache tables are exempt because the framework writes them on ordinary
     * reads. With `SESSION_DRIVER=database` every request updates a row; judging that as a user
     * write would make read-only mode refuse every page it is supposed to let through.
     *
     * The queue tables are deliberately **not** exempt. Dispatching a job from a read-only session
     * is a write with a delay on it, and letting it through would be a laundering route around the
     * whole boundary.
     *
     * @return list<string>
     */
    /**
     * The attempted action, enriched with anything the HTTP envelope alone does not say.
     *
     * One builder for both the enforcement call and the violation event, so the two cannot describe the
     * same request differently — the event is what a reviewer reads to tell a probe from a bug.
     *
     * Livewire identifiers are attached only when the mode actually has rules for them. Decoding a JSON
     * body to discover it was not Livewire is a cost every application would otherwise pay, including
     * the ones not using it.
     */
    private function actionFor(Request $request): AttemptedAction
    {
        $action = AttemptedAction::http(
            method: $request->getMethod(),
            path: $request->path(),
            routeName: $request->route() === null ? null : $request->route()->getName(),
        );

        if ($this->settings->stringList('modes.limited.deny_livewire') === []) {
            return $action;
        }

        $identifiers = LivewireAction::identifiersFrom($request);

        return $identifiers === [] ? $action : $action->withContext(['livewire' => $identifiers]);
    }

    /**
     * Tables the persistence guard must not judge.
     *
     * @return list<string>
     */
    private function exemptTables(): array
    {
        $own = [
            $this->settings->string('audit.table', 'impersonator_audits'),
            $this->settings->string('trail.table', 'impersonator_audit_events'),
            $this->settings->string('tokens.table', 'impersonator_tokens'),
            $this->settings->string('approval.table', 'impersonator_approval_requests'),
        ];

        $framework = $this->settings->stringList('modes.exempt_tables');

        if ($framework === []) {
            $framework = ['sessions', 'cache', 'cache_locks'];
        }

        return array_values(array_unique([...$own, ...$framework]));
    }

    /**
     * 403 with a safe message, plus the event that makes the refusal observable.
     *
     * A read-only operator hitting one write endpoint is a misclick; the same
     * operator hitting several is somebody probing the boundary, and that difference
     * only exists if each refusal is emitted.
     */
    private function refuse(ImpersonationSession $session, Request $request, Decision $decision): never
    {
        $this->events->dispatch(new ModeViolationBlocked(
            $session,
            $this->actionFor($request),
            $decision,
        ));

        // The message is the mode's, which is written for an operator. No internal
        // detail reaches the response.
        throw new HttpException(403, $decision->reason ?? 'That action is not permitted while impersonating.');
    }
}
