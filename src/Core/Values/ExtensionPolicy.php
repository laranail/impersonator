<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use DateInterval;
use DateTimeImmutable;

/**
 * The rules bounding how much longer an impersonation may run.
 *
 * A short `max_duration` is the control; extension is the escape valve that makes a short
 * one usable. Without an escape valve operators set `max_duration` high — a support call
 * that outlasts the window means leaving, re-entering, and losing the thread — and a long
 * window is the thing being avoided. So the design is: a small default window, extendable
 * in place, under a ceiling that cannot be extended past.
 *
 * The ceiling is the part that matters. Unlimited extensions turn ten minutes into an
 * unbounded session ten minutes at a time, which is strictly worse than an honest hour:
 * the configuration reads as tightly bounded and is not. Two independent limits therefore
 * apply, and the stricter one wins — a **count** (`max`) and a **total elapsed duration**
 * measured from the start (`maxTotalMinutes`). The count alone cannot bound total time,
 * because the window length is configurable; the total alone cannot bound how often an
 * operator is nudged to re-justify.
 *
 * Pure and framework-free by design: every input is a primitive, `$now` is injected, and
 * the whole rule set is exercised without a container or a database.
 */
final readonly class ExtensionPolicy
{
    /**
     * @param bool $enabled whether extension is offered at all
     * @param int $minutes length of one extension
     * @param int|null $max how many extensions per impersonation; null is unlimited
     * @param int|null $maxTotalMinutes total lifetime ceiling from `startedAt`; null is unlimited
     * @param int|null $withinMinutes only extend inside the final N minutes; null is any time
     */
    public function __construct(
        public bool $enabled = true,
        public int $minutes = 10,
        public ?int $max = 3,
        public ?int $maxTotalMinutes = 60,
        public ?int $withinMinutes = null,
    ) {}

    /**
     * Whether more time can be granted, and how much.
     *
     * Order is deliberate. The cheap, absolute refusals come first so a caller rendering a
     * button gets the most useful reason: "extensions are off" is a different message from
     * "you have used all three", and both are better than "not now".
     */
    public function evaluate(ImpersonationSession $session, DateTimeImmutable $now): ExtensionGrant
    {
        if (! $this->enabled) {
            return ExtensionGrant::refuse(Decision::deny(
                Decision::EXTENSION_DISABLED,
                'This impersonation cannot be extended.',
            ));
        }

        if (! $session->isActive()) {
            return ExtensionGrant::refuse(Decision::deny(
                Decision::SESSION_TERMINATED,
                'This impersonation has already ended.',
                ['detail' => 'ended'],
            ));
        }

        // Revoked-but-not-yet-closed is the window between an administrator pulling the
        // switch and the target session's next request. Buying time inside it would let an
        // operator outrun their own revocation.
        if ($session->isRevoked()) {
            return ExtensionGrant::refuse(Decision::deny(
                Decision::SESSION_TERMINATED,
                'This impersonation was ended by an administrator.',
                ['detail' => 'revoked'],
            ));
        }

        if ($session->isExpiredAt($now)) {
            return ExtensionGrant::refuse(Decision::deny(
                Decision::SESSION_TERMINATED,
                'This impersonation has expired. Enter again to continue.',
                ['detail' => 'expired'],
            ));
        }

        if ($this->max !== null && $session->extensions >= $this->max) {
            return ExtensionGrant::refuse(Decision::deny(
                Decision::EXTENSION_LIMIT,
                'This impersonation has already been extended as many times as allowed.',
                ['extensions' => $session->extensions, 'max' => $this->max],
            ));
        }

        // An impersonation with no expiry is already unlimited, so there is nothing to
        // extend. Reported as the ceiling rather than as an error: the honest answer to
        // "can I have more time" is that there is no limit to move.
        if ($session->expiresAt === null) {
            return ExtensionGrant::refuse(Decision::deny(
                Decision::EXTENSION_CEILING,
                'This impersonation has no time limit, so there is nothing to extend.',
                ['detail' => 'unlimited'],
            ));
        }

        if ($this->withinMinutes !== null) {
            $opensAt = $session->expiresAt->sub(new DateInterval('PT' . $this->withinMinutes . 'M'));

            if ($now < $opensAt) {
                return ExtensionGrant::refuse(Decision::deny(
                    Decision::EXTENSION_TOO_EARLY,
                    'There is still time left on this impersonation. Extend it closer to the end.',
                    ['opens_at' => $opensAt->format(DATE_ATOM), 'within_minutes' => $this->withinMinutes],
                ));
            }
        }

        $requested = $session->expiresAt->add(new DateInterval('PT' . $this->minutes . 'M'));
        $ceiling = $this->ceilingFor($session);

        if ($ceiling === null) {
            return ExtensionGrant::allow($requested, $session->expiresAt);
        }

        // Already at or past the ceiling: refuse rather than grant nothing. A "success" that
        // moves the expiry by zero seconds reads as working and is not.
        if ($session->expiresAt >= $ceiling) {
            return ExtensionGrant::refuse(Decision::deny(
                Decision::EXTENSION_CEILING,
                'This impersonation has reached the longest it may run. Leave and enter again if you need more time.',
                ['ceiling' => $ceiling->format(DATE_ATOM), 'max_total_minutes' => $this->maxTotalMinutes],
            ));
        }

        // Clamped, not refused. Asking for ten more minutes when four remain under the
        // ceiling should yield four — refusing outright would strand the last minutes of an
        // allowance the configuration does permit.
        return ExtensionGrant::allow(min($requested, $ceiling), $session->expiresAt);
    }

    /** The latest this impersonation may ever expire, or null when unbounded. */
    public function ceilingFor(ImpersonationSession $session): ?DateTimeImmutable
    {
        if ($this->maxTotalMinutes === null) {
            return null;
        }

        return $session->startedAt->add(new DateInterval('PT' . $this->maxTotalMinutes . 'M'));
    }

    /** How many extensions remain, or null when unlimited. */
    public function remainingFor(ImpersonationSession $session): ?int
    {
        return $this->max === null ? null : max(0, $this->max - $session->extensions);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'enabled' => $this->enabled,
            'minutes' => $this->minutes,
            'max' => $this->max,
            'max_total_minutes' => $this->maxTotalMinutes,
            'within_minutes' => $this->withinMinutes,
        ];
    }
}
