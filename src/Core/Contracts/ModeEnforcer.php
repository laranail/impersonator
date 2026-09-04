<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Contracts;

use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * The privilege envelope for one mode — the extension point that makes modes
 * open-ended rather than a fixed enum.
 *
 * Three enforcers ship: `read_only` (unsafe HTTP methods refused, with an
 * optional persistence-level net), `limited` (writes allowed except a
 * configured deny-list of routes, paths, abilities and model classes), and
 * `full` (whatever the target could do). An app registers its own by binding
 * another implementation under a new mode name.
 *
 * Two invariants hold for every implementation:
 *
 *  - The mode comes from `$session`, which is server-side state. An enforcer
 *    must never consult request input to decide which mode applies; that would
 *    let a client pick its own envelope.
 *  - A mode only ever narrows what the target could already do. It is not a
 *    grant mechanism, so an enforcer that allowed something the target lacks
 *    permission for would be a privilege escalation, not a custom mode.
 */
interface ModeEnforcer
{
    /** The mode name this enforcer governs, e.g. `read_only`. */
    public function mode(): string;

    /**
     * Judge one action against the mode.
     *
     * Called on the hot path of every impersonated request, so it must be cheap
     * and side-effect free. Returning a Decision rather than throwing lets the
     * caller log the refusal with its code before choosing a response.
     */
    public function check(AttemptedAction $action, ImpersonationSession $session): Decision;

    /**
     * Whether this mode also needs the persistence-level guard installed —
     * the stricter net that intercepts writes reached through a GET route,
     * which HTTP-method checking alone cannot see.
     */
    public function guardsPersistence(): bool;

    /**
     * Human-readable summary shown in the banner and the API, so an operator can
     * see what they are currently allowed to do.
     */
    public function describe(): string;
}
