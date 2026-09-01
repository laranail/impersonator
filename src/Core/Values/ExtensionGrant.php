<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use DateTimeImmutable;

/**
 * The answer to "may this impersonation have more time, and until when?"
 *
 * A `Decision` alone cannot carry this: the reply to an allowed extension is not merely
 * *yes* but *until this instant*, and the instant may be less than was asked for because
 * the ceiling clamped it. Returning both together keeps the two from being computed by
 * separate calls that could disagree — which is how a request granted against one clock
 * reading gets written against another.
 *
 * @see ExtensionPolicy the rules that produce this
 */
final readonly class ExtensionGrant
{
    private function __construct(
        public Decision $decision,
        public ?DateTimeImmutable $expiresAt = null,
        public ?DateTimeImmutable $previousExpiresAt = null,
    ) {}

    public static function allow(DateTimeImmutable $expiresAt, DateTimeImmutable $previousExpiresAt): self
    {
        return new self(Decision::allow(), $expiresAt, $previousExpiresAt);
    }

    public static function refuse(Decision $decision): self
    {
        return new self($decision);
    }

    /**
     * Both halves must hold. Checking the decision alone would let a construction bug
     * present as an allowed extension with nothing to write.
     */
    public function granted(): bool
    {
        return $this->decision->allowed && $this->expiresAt !== null;
    }

    public function denied(): bool
    {
        return ! $this->granted();
    }

    /** Seconds actually added, which is the clamped amount rather than the amount requested. */
    public function seconds(): int
    {
        if ($this->expiresAt === null || $this->previousExpiresAt === null) {
            return 0;
        }

        return $this->expiresAt->getTimestamp() - $this->previousExpiresAt->getTimestamp();
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'granted' => $this->granted(),
            'expires_at' => $this->expiresAt?->format(DATE_ATOM),
            'seconds' => $this->seconds(),
            'code' => $this->decision->code,
            'reason' => $this->decision->reason,
        ];
    }
}
