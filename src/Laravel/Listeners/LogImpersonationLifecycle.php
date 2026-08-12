<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Listeners;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Log\LogManager;
use Psr\Log\LoggerInterface;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationEnded;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRejected;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationStarted;

/**
 * Writes every lifecycle transition to a PSR-3 channel with structured context.
 *
 * Refusals log at their own, higher level. That asymmetry is the point: a
 * successful impersonation is routine, while an operator repeatedly attempting
 * accounts they cannot reach is the thing an alert should fire on — and it is the
 * signal most impersonation packages never emit at all.
 *
 * The context is deliberately flat scalars keyed consistently across all three
 * events, so a log aggregator can facet on `impersonator`, `target` or
 * `decision` without per-event parsing rules. No token, credential or hash ever
 * appears here.
 */
final readonly class LogImpersonationLifecycle
{
    public function __construct(
        private LogManager $logs,
        private Config $config,
    ) {}

    public function handleStarted(ImpersonationStarted $event): void
    {
        $this->log($this->level(), 'Impersonation started.', [
            'audit_id' => $event->session->auditId,
            'impersonator' => $event->session->impersonator->key(),
            'target' => $event->session->target->key(),
            'mode' => $event->session->mode->name,
            'driver' => $event->session->driver,
            'adapter' => $event->session->adapter,
            'tenant_id' => $event->session->tenantId,
            'reason' => $event->session->reason,
            'expires_at' => $event->session->expiresAt?->format(DATE_ATOM),
        ]);
    }

    public function handleEnded(ImpersonationEnded $event): void
    {
        // An involuntary end is a security event rather than a routine one: a
        // revocation or an expiry says something intervened.
        $level = $event->reason->isInvoluntary() ? $this->rejectionLevel() : $this->level();

        $this->log($level, 'Impersonation ended.', [
            'audit_id' => $event->session->auditId,
            'impersonator' => $event->session->impersonator->key(),
            'target' => $event->session->target->key(),
            'mode' => $event->session->mode->name,
            'ended_by' => $event->reason->value,
            'duration_seconds' => $event->session->durationInSeconds(new \DateTimeImmutable),
        ]);
    }

    public function handleRejected(ImpersonationRejected $event): void
    {
        $this->log($this->rejectionLevel(), 'Impersonation rejected.', [
            'impersonator' => $event->request->impersonator->key(),
            'target' => $event->request->target->key(),
            'mode' => $event->request->mode->name,
            'driver' => $event->request->driver,
            'decision' => $event->decision->code,
            'reason' => $event->decision->reason,
            'context' => $event->decision->context,
            'ip' => $event->request->ip,
        ]);
    }

    /** @param array<string, mixed> $context */
    private function log(string $level, string $message, array $context): void
    {
        if (! $this->config->get('impersonator.logging.enabled', true)) {
            return;
        }

        $this->channel()->log($level, $message, array_filter(
            $context,
            static fn (mixed $value): bool => $value !== null && $value !== [],
        ));
    }

    private function channel(): LoggerInterface
    {
        $channel = $this->config->get('impersonator.logging.channel');

        return is_string($channel) && $channel !== ''
            ? $this->logs->channel($channel)
            : $this->logs->driver();
    }

    private function level(): string
    {
        return $this->normalise($this->config->get('impersonator.logging.level'), 'info');
    }

    private function rejectionLevel(): string
    {
        return $this->normalise($this->config->get('impersonator.logging.rejection_level'), 'warning');
    }

    /**
     * A level PSR-3 recognises. An unrecognised name would make the logger throw
     * on a lifecycle event, so a bad config value degrades to the default rather
     * than turning an impersonation into an exception.
     */
    private function normalise(mixed $level, string $default): string
    {
        $allowed = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'];

        return is_string($level) && in_array(strtolower($level), $allowed, true)
            ? strtolower($level)
            : $default;
    }
}
