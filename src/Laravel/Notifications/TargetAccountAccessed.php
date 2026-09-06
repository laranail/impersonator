<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Lang;
use Illuminate\Notifications\Notification;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

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
        $appName = is_string($name = config('app.name')) && $name !== ''
            ? $name
            : (string) __('laranail-impersonator::notifications.target.fallback_app_name');

        return (new MailMessage)
            ->subject(__('laranail-impersonator::notifications.target.subject', ['app' => $appName]))
            ->line(__('laranail-impersonator::notifications.target.accessed', ['date' => $this->startedAtForHumans()]))
            ->line($this->modeExplanation())
            ->line(__('laranail-impersonator::notifications.target.routine'));
    }

    /** @return array<string, mixed> */
    public function toArray(object $notifiable): array
    {
        // No operator identity, matching the mail body. The audit id is included so a
        // support conversation can be tied back to the trail.
        return [
            'impersonation_audit_id' => $this->session->auditId,
            'mode'                   => $this->session->mode->name,
            'started_at'             => $this->session->startedAt->format(DATE_ATOM),
        ];
    }

    /**
     * Plain-language mode description. A customer told "read_only" learns nothing; told
     * that nothing could be changed, they learn the thing that matters to them.
     */
    private function modeExplanation(): string
    {
        $mode = $this->session->mode->name;
        $key = 'laranail-impersonator::notifications.target.mode.' . $mode;

        return Lang::has($key)
            ? (string) __($key)
            : (string) __('laranail-impersonator::notifications.target.mode.default');
    }

    /**
     * The start time, localised.
     *
     * `Carbon::translatedFormat()`, not `format()`. The previous literal was
     * `'j F Y \a\t H:i T'` — which escapes the **English word "at"** into the format string, so a
     * French locale produced a French month name beside an English preposition. No lang file can fix
     * that, because the offending word is inside a date format rather than in a sentence.
     *
     * `translatedFormat` also localises the month and day names, which plain `format()` never does
     * whatever the application's locale is set to.
     */
    private function startedAtForHumans(): string
    {
        // The locale is passed explicitly. Carbon keeps its *own* locale and does not follow
        // `app()->setLocale()`, so `translatedFormat()` alone would render an English month inside an
        // otherwise translated mail — the same class of half-translated output this change set out to
        // remove, just moved one layer down.
        //
        // Reading the application locale also makes this honour a per-recipient preference for free:
        // Laravel wraps a notification for a `HasLocalePreference` notifiable in `withLocale()`, which
        // is exactly what this then observes.
        // Set as a statement rather than chained: Carbon's `locale()` is typed to return
        // `static|string` (it doubles as a getter), so chaining off it is a union to static analysis.
        // It mutates in place, so this is the same call without the ambiguity — and without a cast.
        $startedAt = Carbon::instance($this->session->startedAt);
        $startedAt->locale(app()->getLocale());

        return $startedAt->translatedFormat('j F Y, H:i T');
    }
}
