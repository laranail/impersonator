<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Exceptions;

/**
 * An operation named an audit row that does not exist.
 *
 * Always a bug rather than a user error: every audit id in circulation was minted
 * by `AuditStore::open()`, so a missing row means state was lost between opening
 * it and acting on it.
 */
final class AuditRowMissing extends ImpersonationException
{
    public static function for(string $auditId): self
    {
        return new self(sprintf('No impersonation audit row found for id [%s].', $auditId));
    }
}
