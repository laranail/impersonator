<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

/**
 * What an attempted extension did, as the store saw it.
 *
 * Pairs the grant with the row it was applied to, because the caller needs both and the
 * store is the only place they are guaranteed to agree. The session inside a locked
 * transaction is the authoritative one; a caller that had already read the row may be
 * holding a copy from before another request extended it.
 *
 * A refusal still carries the session, so a caller can render "expires in 40 seconds, no
 * extensions left" from a single return value rather than querying again to find out why.
 * The one case with no session is the one where none exists: nobody is impersonating. That
 * is null rather than a fabricated row, because a stand-in session here would be a lie the
 * type system stopped anyone from noticing.
 */
final readonly class ExtensionOutcome
{
    public function __construct(
        public ?ImpersonationSession $session,
        public ExtensionGrant $grant,
    ) {}

    public function granted(): bool
    {
        return $this->grant->granted();
    }

    public function denied(): bool
    {
        return $this->grant->denied();
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->grant->toArray() + [
            'extensions' => $this->session->extensions ?? 0,
        ];
    }
}
