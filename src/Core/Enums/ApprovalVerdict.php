<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Enums;

use Simtabi\Laranail\Enumerator\Attributes\Label;
use Simtabi\Laranail\Enumerator\Concerns\HasAttributes;
use Simtabi\Laranail\Enumerator\Contracts\Translatable;
use Simtabi\Laranail\Enumerator\Concerns\IsTranslatable;

/**
 * What one reviewer said about one request.
 *
 * Deliberately two cases and no third. There is no `Abstained`: a reviewer who declines to decide
 * leaves the request pending, which is already expressible, and adding a recorded abstention would
 * raise the question of whether it counts toward quorum — a question with no safe default.
 *
 * Persisted in `impersonator_approval_decisions.verdict`, so the values are a storage contract.
 */
enum ApprovalVerdict: string implements Translatable
{
    use HasAttributes;
    use IsTranslatable;

    #[Label('Approved')]
    case Approved = 'approved';

    #[Label('Denied')]
    case Denied = 'denied';

    /** Pinned, for the reason given on the other Core enums. @see EndReason::translationSlug() */
    public static function translationSlug(): string
    {
        return 'approval_verdict';
    }

    public static function translationNamespace(): string
    {
        return 'laranail-impersonator';
    }

    /**
     * Whether this verdict ends the chain on its own.
     *
     * A single denial is terminal; approvals accumulate. That asymmetry is the whole shape of the
     * control — a reviewer who spots a problem must not have to persuade the others, and failing
     * closed is the only safe reading of a disagreement about access to somebody's account.
     */
    public function isTerminal(): bool
    {
        return $this === self::Denied;
    }
}
