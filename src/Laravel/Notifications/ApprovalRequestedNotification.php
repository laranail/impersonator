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
        $appName = is_string($name = config('app.name')) ? $name : 'Application';

        return (new MailMessage)
            ->subject(__('impersonator::notifications.approval.requested.subject', ['app' => $appName]))
            ->line(__('impersonator::notifications.approval.requested.line'))
            ->line(__('impersonator::notifications.fields.operator', ['value' => $this->request->requester->label ?? $this->request->requester->key()]))
            ->line(__('impersonator::notifications.fields.target', ['value' => $this->request->target->label ?? $this->request->target->key()]))
            ->line(__('impersonator::notifications.fields.mode', ['value' => $this->request->mode->name]))
            ->line(__('impersonator::notifications.fields.reason', ['value' => $this->request->reason ?? __('impersonator::notifications.fields.none_given')]))
            ->line(__('impersonator::notifications.fields.request_id', ['value' => $this->request->id]))
            // An absolute timestamp, deliberately not localised into prose: an approver acting on a
            // deadline needs it unambiguous, and the timezone abbreviation is the part that matters.
            ->line(__('impersonator::notifications.fields.expires', ['value' => $this->request->expiresAt->format('Y-m-d H:i:s T')]))
            ->line(__('impersonator::notifications.approval.requested.action'));
    }

    /** @return array<string, mixed> */
    public function toArray(object $notifiable): array
    {
        return $this->request->toArray();
    }
}
