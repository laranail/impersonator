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
            // A whole subject per outcome, never `'request %s'` with an adjective spliced in. Word
            // order is not universal — a template ending in the outcome cannot be translated
            // correctly into a language that puts it first, and the result reads as machine output.
            ->subject(__(
                'laranail-impersonator::notifications.approval.decided.subject_'.$this->outcome(),
                ['app' => is_string($appName = config('app.name')) ? $appName : 'Application'],
            ))
            ->line($this->headline())
            ->line(__('laranail-impersonator::notifications.fields.target', ['value' => $this->request->target->label ?? $this->request->target->key()]))
            ->line(__('laranail-impersonator::notifications.fields.mode', ['value' => $this->request->mode->name]))
            ->line(__('laranail-impersonator::notifications.fields.request_id', ['value' => $this->request->id]));

        if ($this->request->decisionNote !== null) {
            $message->line(__('laranail-impersonator::notifications.fields.note', ['value' => $this->request->decisionNote]));
        }

        if ($this->request->approved()) {
            // The window matters, and it is the window on the *approval*, not a fresh one. An
            // operator who thinks they have fifteen minutes from reading the mail will find the
            // permit already dead.
            $message->line(__('laranail-impersonator::notifications.approval.decided.window', [
                'date' => $this->request->expiresAt->format('Y-m-d H:i:s T'),
            ]));
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

    /**
     * One complete sentence per outcome, keyed by the same token as the subject.
     *
     * Already complete sentences before this change, which is why they needed no restructuring — only
     * the subject was splicing `outcome()` into a template.
     */
    private function headline(): string
    {
        return match (true) {
            $this->expired => (string) __('laranail-impersonator::notifications.approval.decided.expired'),
            $this->request->approved() => (string) __('laranail-impersonator::notifications.approval.decided.approved'),
            default => (string) __('laranail-impersonator::notifications.approval.decided.denied'),
        };
    }
}
