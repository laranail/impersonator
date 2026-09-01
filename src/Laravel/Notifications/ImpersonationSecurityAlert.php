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
        $appName = is_string($name = config('app.name')) ? $name : 'Application';

        return (new MailMessage)
            ->subject(__('laranail-impersonator::notifications.security.subject', [
                'app' => $appName,
                'summary' => $this->headline(),
            ]))
            ->line($this->headline())
            ->line(__('laranail-impersonator::notifications.fields.operator', ['value' => $this->session->impersonator->label ?? $this->session->impersonator->key()]))
            ->line(__('laranail-impersonator::notifications.fields.target', ['value' => $this->session->target->label ?? $this->session->target->key()]))
            ->line(__('laranail-impersonator::notifications.fields.mode', ['value' => $this->session->mode->name]))
            ->line(__('laranail-impersonator::notifications.fields.reason', ['value' => $this->session->reason ?? __('laranail-impersonator::notifications.fields.none_given')]))
            ->line(__('laranail-impersonator::notifications.fields.audit_id', ['value' => $this->session->auditId]));
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
            'revoked' => (string) __('laranail-impersonator::notifications.security.summary.revoked'),
            'full_mode_enter' => (string) __('laranail-impersonator::notifications.security.summary.full_mode_enter'),
            'expired' => (string) __('laranail-impersonator::notifications.security.summary.expired'),
            default => (string) __('laranail-impersonator::notifications.security.summary.default'),
        };
    }
}
