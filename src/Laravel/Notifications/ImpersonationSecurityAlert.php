<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * Alerts a security channel about an impersonation worth a human look.
 *
 * Fired for full-mode entries and for every revocation, which are the two events that
 * are either the most privileged thing the package can do or a sign somebody intervened.
 * Routine `read_only` support work does not alert, because an alert channel that fires
 * on everything is one nobody reads.
 *
 * Unlike the target notification this *does* name the operator: the audience is the
 * security team, and an alert that omits who did it is not actionable.
 */
class ImpersonationSecurityAlert extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public readonly ImpersonationSession $session,
        public readonly string $trigger,
    ) {}

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject(sprintf(
                '[%s] Impersonation alert: %s',
                is_string($appName = config('app.name')) ? $appName : 'Application',
                $this->headline(),
            ))
            ->line($this->headline())
            ->line(sprintf('Operator: %s', $this->session->impersonator->label ?? $this->session->impersonator->key()))
            ->line(sprintf('Target: %s', $this->session->target->label ?? $this->session->target->key()))
            ->line(sprintf('Mode: %s', $this->session->mode->name))
            ->line(sprintf('Reason: %s', $this->session->reason ?? 'none given'))
            ->line(sprintf('Audit id: %s', $this->session->auditId));
    }

    /** @return array<string, mixed> */
    public function toArray(object $notifiable): array
    {
        // The audit-safe projection: no credential hash and no session id, because an
        // alert is forwarded, pasted into chat and archived in places the audit table
        // is not.
        return [
            'trigger' => $this->trigger,
            'headline' => $this->headline(),
        ] + $this->session->toArray();
    }

    private function headline(): string
    {
        return match ($this->trigger) {
            'revoked' => 'An impersonation was revoked by an administrator.',
            'full_mode_enter' => 'An operator entered an account with full access.',
            'expired' => 'An impersonation was force-ended after reaching its time limit.',
            default => 'An impersonation event occurred.',
        };
    }
}
