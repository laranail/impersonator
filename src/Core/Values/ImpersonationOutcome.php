<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use Simtabi\Laranail\Impersonator\Core\Exceptions\NotImpersonating;

/**
 * What a driver produced from `begin()`.
 *
 * Two shapes, and keeping them distinct matters. `started` means the target is
 * authenticated here and now. `pending` means a single-use token was issued and
 * nothing has happened yet — the operator must still follow `acceptUrl` for the
 * impersonation to exist. Treating a pending handoff as a live session is how a
 * UI ends up showing "now impersonating" for a session that was never created.
 *
 * `credential` is populated at most once, on the object returned to the caller
 * that caused it, and its secret is never persisted or recoverable afterwards.
 */
final readonly class ImpersonationOutcome
{
    private function __construct(
        public ImpersonationSession $session,
        public bool $pending,
        public ?string $acceptUrl = null,
        public ?Credential $credential = null,
        public ?string $redirectTo = null,
    ) {}

    /** The target is authenticated; the impersonation is live. */
    public static function started(
        ImpersonationSession $session,
        ?Credential $credential = null,
        ?string $redirectTo = null,
    ): self {
        return new self(
            session: $session,
            pending: false,
            credential: $credential,
            redirectTo: $redirectTo,
        );
    }

    /**
     * A token was issued and the handoff is not complete. The audit row exists
     * and is open, but no authentication has occurred.
     */
    public static function pending(
        ImpersonationSession $session,
        string $acceptUrl,
        ?string $redirectTo = null,
    ): self {
        return new self(
            session: $session,
            pending: true,
            acceptUrl: $acceptUrl,
            redirectTo: $redirectTo,
        );
    }

    public function isStarted(): bool
    {
        return ! $this->pending;
    }

    public function auditId(): string
    {
        return $this->session->auditId;
    }

    /**
     * The URL the operator must follow to complete a pending handoff.
     *
     * @throws NotImpersonating when the outcome is already started, since there
     *                          is no handoff left to perform.
     */
    public function acceptUrl(): string
    {
        if (! $this->pending || $this->acceptUrl === null) {
            throw NotImpersonating::make();
        }

        return $this->acceptUrl;
    }

    /**
     * The audit-safe projection. Never includes the credential secret, and never
     * includes the accept URL — that URL contains a live single-use token, so
     * serialising it into anything durable defeats the point of hashing it.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'pending' => $this->pending,
            'session' => $this->session->toArray(),
            'redirect_to' => $this->redirectTo,
            'credential' => $this->credential?->toAuditArray(),
        ];
    }
}
