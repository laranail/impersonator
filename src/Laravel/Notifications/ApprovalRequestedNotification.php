<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;

/**
 * Asks an authorised operator to decide a break-glass request.
 *
 * Names the requester, the target, the mode and the stated reason — an approver deciding
 * without those is not reviewing anything, they are clicking a button. The expiry is included
 * for the same reason: knowing the request dies in fifteen minutes is what makes it urgent
 * enough to read now.
 *
 * Carries **no approval link and no credential**. The decision is made through the application's
 * own authenticated surface, so there is nothing in this message that grants anything — a mail
 * with a one-click approve token would move the four-eyes control into an inbox.
 */
class ApprovalRequestedNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(public readonly ApprovalRequest $request) {}

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject(sprintf(
                '[%s] Impersonation approval requested',
                is_string($appName = config('app.name')) ? $appName : 'Application',
            ))
            ->line('An operator is asking for approval to impersonate an account.')
            ->line(sprintf('Operator: %s', $this->request->requester->label ?? $this->request->requester->key()))
            ->line(sprintf('Target: %s', $this->request->target->label ?? $this->request->target->key()))
            ->line(sprintf('Mode: %s', $this->request->mode->name))
            ->line(sprintf('Reason: %s', $this->request->reason ?? 'none given'))
            ->line(sprintf('Request id: %s', $this->request->id))
            ->line(sprintf('Expires: %s', $this->request->expiresAt->format('Y-m-d H:i:s T')))
            ->line('Approve or deny it from your administration area. You cannot approve your own request.');
    }

    /** @return array<string, mixed> */
    public function toArray(object $notifiable): array
    {
        return $this->request->toArray();
    }
}
