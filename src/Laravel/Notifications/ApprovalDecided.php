<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;

/**
 * Tells the requester what happened to their break-glass request.
 *
 * Sent for all three outcomes, expiry included. An operator left wondering whether they were
 * refused or simply never answered will ask a colleague to approve it out of band, which is how
 * a control gets routed around — so "nobody replied" is a message worth sending.
 */
class ApprovalDecided extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public readonly ApprovalRequest $request,
        public readonly bool $expired = false,
    ) {}

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $message = (new MailMessage)
            ->subject(sprintf(
                '[%s] Impersonation request %s',
                is_string($appName = config('app.name')) ? $appName : 'Application',
                $this->outcome(),
            ))
            ->line($this->headline())
            ->line(sprintf('Target: %s', $this->request->target->label ?? $this->request->target->key()))
            ->line(sprintf('Mode: %s', $this->request->mode->name))
            ->line(sprintf('Request id: %s', $this->request->id));

        if ($this->request->decisionNote !== null) {
            $message->line(sprintf('Note from the approver: %s', $this->request->decisionNote));
        }

        if ($this->request->approved()) {
            // The window matters, and it is the window on the *approval*, not a fresh one. An
            // operator who thinks they have fifteen minutes from reading the mail will find the
            // permit already dead.
            $message->line(sprintf(
                'You may now start the impersonation once, until %s.',
                $this->request->expiresAt->format('Y-m-d H:i:s T'),
            ));
        }

        return $message;
    }

    /** @return array<string, mixed> */
    public function toArray(object $notifiable): array
    {
        return ['expired' => $this->expired] + $this->request->toArray();
    }

    private function outcome(): string
    {
        return match (true) {
            $this->expired => 'expired',
            $this->request->approved() => 'approved',
            default => 'denied',
        };
    }

    private function headline(): string
    {
        return match (true) {
            $this->expired => 'Your impersonation request expired before anyone decided it.',
            $this->request->approved() => 'Your impersonation request was approved.',
            default => 'Your impersonation request was denied.',
        };
    }
}
