<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Enums;

/**
 * What kind of thing an AuthAdapter handed back to authenticate the target.
 *
 * `Session` means no credential left the server — the adapter mutated the
 * session in place. Every other case is a bearer credential that was shown to
 * the caller exactly once and can never be retrieved again.
 */
enum CredentialType: string
{
    case Session = 'session';

    case SanctumToken = 'sanctum_token';

    case PassportToken = 'passport_token';

    case Jwt = 'jwt';

    /** True when a secret was returned to the caller and must be treated as one. */
    public function isBearer(): bool
    {
        return $this !== self::Session;
    }
}
