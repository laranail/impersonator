<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Illuminate\Contracts\Session\Session;
use Illuminate\Session\CookieSessionHandler;
use Illuminate\Session\NullSessionHandler;
use SessionHandlerInterface;
use Simtabi\Laranail\Impersonator\Core\Contracts\FailureReporter;
use Simtabi\Laranail\Impersonator\Core\Enums\Criticality;
use Simtabi\Laranail\Impersonator\Core\Exceptions\OperationFailed;
use Throwable;

/**
 * Destroys another user's session by id, without being inside it.
 *
 * This is what upgrades revocation from "ends on the target's next request" to "the
 * session is gone now". The distinction matters in the case revocation exists for: an
 * operator who should not be in an account, who might sit on an open page for an hour
 * before making another request.
 *
 * The mechanism is deliberately the session **handler**, not a driver-specific hack.
 * `SessionHandlerInterface::destroy($id)` is implemented by every Laravel session driver
 * — file unlinks the file, database deletes the row, redis and memcached forget the key —
 * so one call covers all of them and a driver added later works without a change here.
 * Reaching into `storage/framework/sessions` directly would have handled `file` and
 * nothing else.
 *
 * Two drivers genuinely cannot be reached from outside, and the honest answer is to say
 * so rather than pretend:
 *
 *  - **`array`** keeps sessions in process memory, so another process has nothing to
 *    destroy.
 *  - **`cookie`** stores the payload in the client's own cookie. Nothing server-side
 *    holds it, so no server can delete it.
 *
 * For those, revocation falls back to the enforcement middleware — which is why that
 * middleware exists as well as this, rather than instead of it.
 */
final readonly class SessionTerminator
{
    public function __construct(
        private Session $session,
        private Settings $settings,
        private FailureReporter $reporter,
    ) {}

    /**
     * Destroy the session with this id.
     *
     * Returns false rather than throwing when it could not: a revocation must complete
     * regardless, because the audit flag plus the middleware is already a correct
     * termination path. Failing here would leave the row unmarked and the impersonation
     * running, which is worse than a slower stop.
     */
    public function terminate(string $sessionId): bool
    {
        if ($sessionId === '' || ! $this->settings->bool('session.destroy_on_revoke', true)) {
            return false;
        }

        if (! $this->canTerminate()) {
            $this->reporter->warn('Impersonator: session cannot be destroyed out of band.', [
                'operation' => 'impersonator.session.terminate',
                'expected' => 'a server-side session driver',
                'actual' => sprintf('driver [%s] holds no server-side session record', $this->driver()),
                'decision' => 'tolerated, revocation enforced on the next request instead',
            ]);

            return false;
        }

        try {
            // Never destroy the caller's own session. An administrator revoking somebody
            // else must not be logged out by doing so — and with one guard for both sides
            // the ids can be closer together than is comfortable.
            if ($sessionId === $this->session->getId()) {
                return false;
            }

            return $this->handler()->destroy($sessionId);
        } catch (Throwable $failure) {
            $this->reporter->report(OperationFailed::from(
                operation: 'impersonator.session.terminate',
                criticality: Criticality::Degradable,
                previous: $failure,
                expected: 'the impersonated session to be destroyed',
                // No session id: it is a live credential for as long as the session
                // lives, and a failing termination is exactly when it would get logged.
                identifiers: ['driver' => $this->driver()],
            ));

            return false;
        }
    }

    /**
     * Whether this installation can destroy a session from outside it.
     *
     * Reported by the doctor command, because "revocation is immediate" and "revocation
     * takes effect on the next request" are different enough operationally that an
     * operator should not have to infer which one they have.
     */
    public function canTerminate(): bool
    {
        if (! $this->settings->bool('session.destroy_on_revoke', true)) {
            return false;
        }

        // Detected by handler class rather than by the config name, so a custom driver
        // registered under any name is judged on what it actually is.
        $handler = $this->handler();

        return ! $handler instanceof CookieSessionHandler
            && ! $handler instanceof NullSessionHandler;
    }

    /** A human explanation for the doctor command. */
    public function explain(): string
    {
        if (! $this->settings->bool('session.destroy_on_revoke', true)) {
            return 'Disabled by session.destroy_on_revoke; revocation takes effect on the '
                . "target's next request.";
        }

        return $this->canTerminate()
            ? sprintf('Revocation destroys the session immediately (driver: %s).', $this->driver())
            : sprintf(
                'Driver [%s] keeps no server-side session record, so revocation takes effect '
                . "on the target's next request.",
                $this->driver(),
            );
    }

    public function driver(): string
    {
        $driver = config('session.driver');

        return is_string($driver) && $driver !== '' ? $driver : 'unknown';
    }

    /**
     * The session's own storage handler.
     *
     * This is the whole mechanism: `destroy($id)` is part of PHP's SessionHandlerInterface,
     * so every Laravel driver implements it and one call reaches all of them.
     */
    private function handler(): SessionHandlerInterface
    {
        return $this->session->getHandler();
    }
}
