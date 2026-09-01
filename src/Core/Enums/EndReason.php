<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Enums;

use Simtabi\Laranail\Enumerator\Attributes\Label;
use Simtabi\Laranail\Enumerator\Concerns\HasAttributes;
use Simtabi\Laranail\Enumerator\Concerns\IsTranslatable;
use Simtabi\Laranail\Enumerator\Contracts\Translatable;

/**
 * Why an impersonation stopped. A genuinely closed set, so unlike Mode this is
 * a real enum. Persisted in `impersonator_audits.ended_by`.
 *
 * `label()` resolves in three steps — a translation key, then the `#[Label]` attribute, then a
 * humanised case name — so an application may localise these without this package shipping a
 * locale, and gets the English string for free if it does not.
 *
 * The `value` is the contract and the label is not. Values are persisted in `ended_by`, returned
 * from the API as `ended_by`, and matched in logs; they must never be translated. Anything
 * branching on an end reason branches on the case or the value.
 */
enum EndReason: string implements Translatable
{
    use HasAttributes;
    use IsTranslatable;

    /** The impersonator explicitly left, or the target session logged out. */
    #[Label('Left')]
    case Left = 'left';

    /** max_duration elapsed, or the issued credential outlived its TTL. */
    #[Label('Expired')]
    case Expired = 'expired';

    /** An administrator killed it remotely through the revocation switch. */
    #[Label('Revoked')]
    case Revoked = 'revoked';

    /**
     * The session backing the impersonation vanished without a leave — the
     * cookie was dropped, the session store was flushed, or the process died.
     * Recorded on the next reconciliation rather than left dangling as active,
     * because a row that is open forever reads as an ongoing breach.
     */
    #[Label('Session lost')]
    case SessionLost = 'session_lost';

    /**
     * The translation slug, pinned rather than derived.
     *
     * `IsTranslatable::translationSlug()` defaults to `class_basename(static::class)`, and
     * `class_basename()` is a Laravel helper called without a `function_exists()` guard — the only
     * unguarded one in that whole trait. Overriding it is what keeps these enums usable outside a
     * booted Laravel application, where they fall back to the `#[Label]` attributes above.
     *
     * Pinning it also fixes the key: a class rename would otherwise silently move every
     * translation key and fall back to English without saying so.
     */
    public static function translationSlug(): string
    {
        return 'end_reason';
    }

    public static function translationNamespace(): string
    {
        return 'laranail-impersonator';
    }

    /** Whether the impersonation was ended by someone other than its owner. */
    public function isInvoluntary(): bool
    {
        return $this !== self::Left;
    }
}
