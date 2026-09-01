<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use DateTimeImmutable;
use SensitiveParameter;
use Stringable;

/**
 * A single-use handoff token.
 *
 * The plaintext exists only on the instance returned by the generator and is
 * never persisted: TokenRepository stores `hash` and looks rows up by it, so a
 * database leak yields nothing redeemable. Both `__toString` and the debug
 * representation are scrubbed, because the usual way a secret ends up in a log
 * file is an exception trace or a `dd()`, not a deliberate write.
 */
final readonly class Token implements Stringable
{
    public function __construct(
        #[SensitiveParameter]
        private string $plaintext,
        public string $hash,
        public DateTimeImmutable $expiresAt,
    ) {}

    /**
     * Keeps the plaintext out of stack traces, `var_dump` and any logger that
     * serialises context objects.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return [
            'plaintext' => '[redacted]',
            'hash' => $this->hash,
            'expiresAt' => $this->expiresAt->format(DATE_ATOM),
        ];
    }

    public function __toString(): string
    {
        return '[redacted impersonation token]';
    }

    /**
     * The raw value. Only ever handed to URL building and the one-time
     * response; treat every call site as a place a secret can escape.
     */
    public function plaintext(): string
    {
        return $this->plaintext;
    }

    public function isExpiredAt(DateTimeImmutable $now): bool
    {
        return $now > $this->expiresAt;
    }
}
