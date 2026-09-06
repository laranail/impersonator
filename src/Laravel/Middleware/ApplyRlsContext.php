<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Middleware;

use Closure;
use Throwable;
use Illuminate\Http\Request;
use Illuminate\Database\Connection;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Database\ConnectionResolverInterface;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Simtabi\Laranail\Impersonator\Laravel\Support\RlsContext;

/**
 * Publishes the impersonation context to PostgreSQL, so an RLS policy can see it.
 *
 * Optional, off unless `rls.enabled`, and **not required** for the main RLS fix — that one is reading
 * {@see RlsContext::effective()} in the application's own scoping layer instead of `auth()->id()`. What
 * this adds is defence in depth: a policy can then refuse writes under `read_only` at the *database*
 * level, independently of the PHP guard, which is the strongest form of the guarantee that mode
 * advertises.
 *
 * ### Why the GUCs are set per transaction and not once here
 *
 * They are transaction-scoped (`set_config(…, true)`), and transaction scope does not survive a
 * request. That is the deliberate trade: session scope *would* survive, and would also leak to the next
 * client that receives the connection under PgBouncer in transaction mode — a data breach, and the most
 * commonly cited RLS footgun there is.
 *
 * So this middleware hooks `beforeExecuting` to set them at the start of each transaction, and
 * `Illuminate`'s own transaction events to catch explicit ones. A statement outside any transaction
 * gets them too, because PostgreSQL wraps a bare statement in an implicit transaction and the config
 * lives exactly as long.
 *
 * ### Failure is degradable, deliberately
 *
 * A `set_config` that throws — wrong driver, connection gone — must not refuse the request. This
 * publishes context for *another* layer's benefit; it is not itself the control. The mode guard in PHP
 * remains primary, which is also why only-RLS is the wrong configuration: a write blocked purely by a
 * policy cannot be reported as a `ModeViolationBlocked` event, so the boundary probe becomes invisible.
 */
final readonly class ApplyRlsContext
{
    public function __construct(
        private RlsContext $context,
        private Settings $settings,
        private ConnectionResolverInterface $connections,
    ) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->settings->bool('rls.enabled', false) || ! $this->context->isImpersonating()) {
            return $next($request);
        }

        $connection = $this->connections->connection(
            $this->settings->nullableString('rls.connection'),
        );

        // PostgreSQL only. `set_config` is not portable, and silently running nothing elsewhere is
        // better than a driver error on every impersonated request — the doctor reports the mismatch.
        //
        // Narrowed to the concrete `Connection` because `getDriverName()` is not on
        // `ConnectionInterface`: a custom implementation may legitimately not have it, and that is a
        // connection this middleware cannot make claims about.
        if (! $connection instanceof Connection || $connection->getDriverName() !== 'pgsql') {
            return $next($request);
        }

        try {
            $this->context->applyTo($connection);
        } catch (Throwable) {
            // Degradable: this publishes context for another layer, and is not itself the control.
        }

        return $next($request);
    }
}
