<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Illuminate\Database\ConnectionInterface;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/**
 * The impersonation context, for a PostgreSQL row-level-security policy to scope on.
 *
 * RLS matters more here than in most packages, and for one specific reason: if an application scopes
 * rows by a session GUC that still names the **operator**, an impersonated session sees the operator's
 * rows while claiming to be the customer. That is the exact inversion impersonation exists to avoid —
 * the support engineer looking at their own data and believing it is the customer's.
 *
 * **This package does not own RLS state, and should not.** Whatever already establishes the context
 * owns it. What is owed is two things: making the effective identity available so that layer can scope
 * to the right person, and not silently breaking the package's own audit trail under RLS.
 *
 * ### Two rules that are not style choices
 *
 * **`select set_config(?, ?, true)` with bindings, never `SET LOCAL app.x = '…'`.** `SET` cannot take a
 * bind parameter, so the obvious implementation interpolates the value — an SQL injection hole on a
 * path that handles identity. `set_config` is a function call and takes parameters properly.
 *
 * **The third argument is `true`, meaning transaction-scoped.** With PgBouncer in transaction mode a
 * session-scoped GUC **leaks to the next client that receives the connection**: a data breach, and the
 * single most-cited RLS footgun. Transaction scope cannot leak because the transaction ends.
 *
 * The cost of transaction scope is that it does not survive a request, which is why
 * {@see applyTo()} is called per transaction rather than once per request.
 */
final readonly class RlsContext
{
    public function __construct(
        private ImpersonationManager $impersonator,
        private Settings $settings,
    ) {}

    /**
     * The identity an application's own scoping should use — the target while impersonating.
     *
     * **This is the whole fix for the inversion**, and it is a one-line change in the host's code once
     * they know to make it: read this rather than `auth()->id()`.
     */
    public function effective(): ?Identity
    {
        $session = $this->impersonator->current();

        if ($session !== null) {
            return $session->target;
        }

        $operator = $this->impersonator->currentImpersonatorOrNull();

        // Null when nobody is authenticated either — a queue worker, a console command. A caller
        // scoping on this must handle that, and returning a fabricated identity would be worse: it
        // would scope somebody's rows to a person who is not there.
        return $operator === null ? null : $this->impersonator->identities()->fromUser($operator);
    }

    /** The operator behind the request, or null when nobody is impersonating. */
    public function operator(): ?Identity
    {
        return $this->impersonator->current()?->impersonator;
    }

    public function isImpersonating(): bool
    {
        return $this->impersonator->current() !== null;
    }

    /**
     * The GUCs this package sets, as name => value.
     *
     * Exposed separately from {@see applyTo()} so a host can inspect or extend the set — and so a test
     * can assert the values without a live PostgreSQL.
     *
     * @return array<string, string>
     */
    public function gucs(): array
    {
        $session = $this->impersonator->current();

        if ($session === null) {
            return [];
        }

        $prefix = $this->settings->string('rls.prefix', 'app');

        return [
            $prefix . '.impersonated_user_id'   => (string) $session->target->id,
            $prefix . '.impersonated_user_type' => $session->target->type,
            $prefix . '.impersonator_id'        => (string) $session->impersonator->id,
            $prefix . '.impersonation_mode'     => $session->mode->name,
            $prefix . '.impersonation_audit_id' => $session->auditId,
        ];
    }

    /**
     * Set the GUCs on a connection, transaction-scoped.
     *
     * Returns how many were set, so a caller can log or assert. Nothing is set when no impersonation is
     * active — an ordinary request must not carry a stale impersonation context, and clearing is not the
     * same as never setting: transaction scope means there is nothing to clear.
     */
    public function applyTo(ConnectionInterface $connection): int
    {
        $applied = 0;

        foreach ($this->gucs() as $name => $value) {
            // `select set_config(?, ?, true)` — a function call with real bindings. The `true` is
            // transaction scope, which is what stops a GUC leaking to the next PgBouncer client.
            $connection->select('select set_config(?, ?, true)', [$name, $value]);
            $applied++;
        }

        return $applied;
    }
}
