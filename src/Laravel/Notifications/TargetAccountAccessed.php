<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * Tells a user their account was accessed by support.
 *
 * A transparency and GDPR-posture choice rather than a security control, which is why it
 * is off by default: some products want customers told every time, others handle
 * disclosure through a contract or a support ticket, and this package should not decide
 * that for them.
 *
 * Deliberately says nothing about *who* accessed the account. Naming the operator would
 * hand every customer the identity of individual staff, and the audit trail already
 * records it for anyone with a legitimate reason to ask.
 *
 * Queued, so a disclosure email cannot slow down or fail the impersonation it describes.
 */
class TargetAccountAccessed extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(public readonly ImpersonationSession $session) {}

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        $channels = app(Settings::class)->stringList('notifications.target_channels');

        return $channels === [] ? ['mail'] : $channels;
    }

    public function toMail(object $notifiable): MailMessage
    {
        $appName = is_string($name = config('app.name')) && $name !== '' ? $name : 'Our team';

        return (new MailMessage)
            ->subject(sprintf('%s accessed your account', $appName))
            ->line(sprintf(
                'A member of our support team accessed your account on %s.',
                $this->session->startedAt->format('j F Y \a\t H:i T'),
            ))
            ->line($this->modeExplanation())
            ->line('This is a routine part of helping with a support request. If you were '
                . 'not expecting it, please reply to this message.');
    }

    /** @return array<string, mixed> */
    public function toArray(object $notifiable): array
    {
        // No operator identity, matching the mail body. The audit id is included so a
        // support conversation can be tied back to the trail.
        return [
            'impersonation_audit_id' => $this->session->auditId,
            'mode' => $this->session->mode->name,
            'started_at' => $this->session->startedAt->format(DATE_ATOM),
        ];
    }

    /**
     * Plain-language mode description. A customer told "read_only" learns nothing; told
     * that nothing could be changed, they learn the thing that matters to them.
     */
    private function modeExplanation(): string
    {
        return match ($this->session->mode->name) {
            'read_only' => 'They could view your account but could not change anything.',
            'limited' => 'They could help with your account, but could not change your '
                . 'password, security settings or billing details.',
            default => 'They had the same access to your account that you do.',
        };
    }
}
