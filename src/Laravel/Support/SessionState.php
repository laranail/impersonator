<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use DateTimeImmutable;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Session\Session;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Values\Guards;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;

/**
 * The server-side record of an in-progress impersonation, kept in the session.
 *
 * This is what makes the mode tamper-proof. The active mode is read from here on
 * every request and never from the request itself, so a client cannot declare its
 * own privilege envelope — the only path to a different mode is to leave and
 * re-enter, which mints a new audit row.
 *
 * Session data survives id regeneration (`migrate` preserves the payload), so
 * writing this before or after the rotation is equally safe.
 */
final readonly class SessionState
{
    public function __construct(
        private Session $session,
        private Config $config,
    ) {}

    public function put(ImpersonationSession $impersonation): void
    {
        $this->session->put($this->key(), [
            'audit_id' => $impersonation->auditId,
            'impersonator' => $impersonation->impersonator->toArray(),
            'target' => $impersonation->target->toArray(),
            'mode' => $impersonation->mode->name,
            'guards' => $impersonation->guards->toArray(),
            'driver' => $impersonation->driver,
            'adapter' => $impersonation->adapter,
            'tenant_id' => $impersonation->tenantId,
            'session_id' => $impersonation->sessionId,
            'credential_hash' => $impersonation->credentialHash,
            'reason' => $impersonation->reason,
            'started_at' => $impersonation->startedAt->getTimestamp(),
            'expires_at' => $impersonation->expiresAt?->getTimestamp(),
            'extensions' => $impersonation->extensions,
            'metadata' => $impersonation->metadata,
        ]);
    }

    /**
     * Rebuild the impersonation from session state, or null.
     *
     * Returns null rather than throwing on malformed state: a half-written or
     * hand-edited payload means "not impersonating", which fails closed. Throwing
     * would break every page for a user whose session went bad.
     */
    public function get(): ?ImpersonationSession
    {
        $state = $this->session->get($this->key());

        if (! is_array($state)) {
            return null;
        }

        $auditId = $state['audit_id'] ?? null;
        $impersonator = $this->identity($state['impersonator'] ?? null);
        $target = $this->identity($state['target'] ?? null);
        $mode = $state['mode'] ?? null;

        if (! is_string($auditId) || $impersonator === null || $target === null || ! is_string($mode)) {
            return null;
        }

        $guards = is_array($state['guards'] ?? null) ? $state['guards'] : [];

        return new ImpersonationSession(
            auditId: $auditId,
            impersonator: $impersonator,
            target: $target,
            mode: Mode::of($mode),
            guards: new Guards(
                impersonator: $this->string($guards['impersonator'] ?? null) ?? 'web',
                target: $this->string($guards['target'] ?? null) ?? 'web',
            ),
            driver: $this->string($state['driver'] ?? null) ?? 'session',
            adapter: $this->string($state['adapter'] ?? null) ?? 'session',
            startedAt: $this->timestamp($state['started_at'] ?? null) ?? new DateTimeImmutable,
            tenantId: $this->string($state['tenant_id'] ?? null),
            sessionId: $this->string($state['session_id'] ?? null),
            credentialHash: $this->string($state['credential_hash'] ?? null),
            reason: $this->string($state['reason'] ?? null),
            expiresAt: $this->timestamp($state['expires_at'] ?? null),
            metadata: is_array($state['metadata'] ?? null) ? Settings::stringKeyed($state['metadata']) : [],
            extensions: is_int($state['extensions'] ?? null) ? max(0, $state['extensions']) : 0,
        );
    }

    public function has(): bool
    {
        return $this->get() !== null;
    }

    public function forget(): void
    {
        $this->session->forget($this->key());
    }

    /**
     * Record why an impersonation ended, for one request, so the page the
     * operator lands on can say what happened.
     *
     * Flashed rather than stored: an involuntary end is worth telling someone
     * about once, and a message that outlived its request would report a
     * revocation on every subsequent page.
     */
    public function flashEnded(EndReason $reason): void
    {
        $this->session->flash($this->key().'_ended', $reason->value);
    }

    public function endedReason(): ?EndReason
    {
        $value = $this->session->get($this->key().'_ended');

        return is_string($value) ? EndReason::tryFrom($value) : null;
    }

    public function key(): string
    {
        $key = $this->config->get('laranail.impersonator.session.key', 'impersonator');

        return is_string($key) && $key !== '' ? $key : 'impersonator';
    }

    private function identity(mixed $data): ?Identity
    {
        if (! is_array($data)) {
            return null;
        }

        $type = $data['type'] ?? null;
        $id = $data['id'] ?? null;

        if (! is_string($type) || (! is_int($id) && ! is_string($id))) {
            return null;
        }

        return new Identity($type, $id, $this->string($data['label'] ?? null));
    }

    private function string(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    private function timestamp(mixed $value): ?DateTimeImmutable
    {
        return is_int($value) ? (new DateTimeImmutable)->setTimestamp($value) : null;
    }
}
