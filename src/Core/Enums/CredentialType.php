<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Enums;

use Simtabi\Laranail\Enumerator\Attributes\Label;
use Simtabi\Laranail\Enumerator\Concerns\HasAttributes;
use Simtabi\Laranail\Enumerator\Concerns\IsTranslatable;
use Simtabi\Laranail\Enumerator\Contracts\Translatable;

/**
 * What kind of thing an AuthAdapter handed back to authenticate the target.
 *
 * `Session` means no credential left the server — the adapter mutated the
 * session in place. Every other case is a bearer credential that was shown to
 * the caller exactly once and can never be retrieved again.
 *
 * Labelled for a UI that offers a choice of adapter. The `value` remains the contract — it is what
 * an audit row records and what the API returns.
 */
enum CredentialType: string implements Translatable
{
    use HasAttributes;
    use IsTranslatable;

    #[Label('Session')]
    case Session = 'session';

    #[Label('Sanctum token')]
    case SanctumToken = 'sanctum_token';

    #[Label('Passport token')]
    case PassportToken = 'passport_token';

    #[Label('JWT')]
    case Jwt = 'jwt';

    /** True when a secret was returned to the caller and must be treated as one. */
    public function isBearer(): bool
    {
        return $this !== self::Session;
    }

    /**
     * Pinned rather than derived. `IsTranslatable::translationSlug()` defaults to
     * `class_basename()`, a Laravel helper called without a `function_exists()` guard — the only
     * unguarded one in that trait. Overriding it keeps this enum usable outside a booted
     * application, and stops a class rename silently relocating every translation key.
     */
    public static function translationSlug(): string
    {
        return 'credential_type';
    }

    public static function translationNamespace(): string
    {
        return 'laranail-impersonator';
    }
}
