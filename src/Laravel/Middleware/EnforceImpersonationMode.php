<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Middleware;

use Closure;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Simtabi\Laranail\Impersonator\Core\Events\ModeViolationBlocked;
use Simtabi\Laranail\Impersonator\Core\Support\ModeRegistry;
use Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

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
    ) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        $session = $this->impersonator->current();

        if ($session === null) {
            return $next($request);
        }

        $enforcer = $this->modes->enforcer($session->mode);

        $decision = $enforcer->check(
            AttemptedAction::http(
                method: $request->getMethod(),
                path: $request->path(),
                routeName: $request->route() === null ? null : $request->route()->getName(),
            ),
            $session,
        );

        if ($decision->denied()) {
            $this->refuse($session, $request, $decision);
        }

        if ($enforcer->guardsPersistence()) {
            $this->installPersistenceGuard($session, $request);
        }

        return $next($request);
    }

    /**
     * The stricter net: intercept at the database layer, before the statement runs.
     *
     * `beforeExecuting` is the only hook that sees every write — Eloquent saves,
     * query-builder updates and raw statements alike. The cost is that it aborts
     * mid-request, so a controller that had already written before reaching the
     * denied statement leaves partial work behind unless it was in a transaction.
     * That is why `prevent_writes` is off by default and documented as the strict
     * setting rather than the recommended one.
     */
    private function installPersistenceGuard(ImpersonationSession $session, Request $request): void
    {
        $enforcer = $this->modes->enforcer($session->mode);

        DB::beforeExecuting(function (string $query, array $bindings, $connection) use (
            $session,
            $request,
            $enforcer,
        ): void {
            $operation = $this->writeVerb($query);

            if ($operation === null) {
                return;
            }

            $decision = $enforcer->check(
                AttemptedAction::write(
                    modelClass: $this->tableFrom($query) ?? 'unknown',
                    operation: $operation,
                    path: $request->path(),
                ),
                $session,
            );

            if ($decision->denied()) {
                $this->refuse($session, $request, $decision);
            }
        });
    }

    /**
     * The write verb a statement begins with, or null for a read.
     *
     * Matched on the leading keyword only. Anything that is not plainly a read is
     * treated as a write, so an unrecognised statement fails closed.
     */
    private function writeVerb(string $query): ?string
    {
        $normalised = ltrim($query);

        if (preg_match('/^(insert|update|delete|replace|truncate|drop|alter|create)\b/i', $normalised, $m) === 1) {
            return strtolower($m[1]);
        }

        return null;
    }

    /** Best-effort table name, for the report. Never used to make the decision. */
    private function tableFrom(string $query): ?string
    {
        if (preg_match('/^\s*(?:insert\s+into|update|delete\s+from|replace\s+into)\s+[`"\[]?([\w.]+)/i', $query, $m) === 1) {
            return $m[1];
        }

        return null;
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
            AttemptedAction::http(
                $request->getMethod(),
                $request->path(),
                $request->route() === null ? null : $request->route()->getName(),
            ),
            $decision,
        ));

        // The message is the mode's, which is written for an operator. No internal
        // detail reaches the response.
        throw new HttpException(403, $decision->reason ?? 'That action is not permitted while impersonating.');
    }
}
