<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Listeners;

use Closure;
use Illuminate\Contracts\Events\Dispatcher as Events;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use Simtabi\Laranail\Impersonator\Core\Contracts\ApprovalStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\FailureReporter;
use Simtabi\Laranail\Impersonator\Core\Enums\Criticality;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalDenied;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalGranted;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalRequested;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationExpired;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRevoked;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationStarted;
use Simtabi\Laranail\Impersonator\Core\Events\TargetNotified;
use Simtabi\Laranail\Impersonator\Core\Exceptions\OperationFailed;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Notifications\ApprovalDecided;
use Simtabi\Laranail\Impersonator\Laravel\Notifications\ApprovalRequestedNotification;
use Simtabi\Laranail\Impersonator\Laravel\Notifications\ImpersonationSecurityAlert;
use Simtabi\Laranail\Impersonator\Laravel\Notifications\TargetAccountAccessed;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Throwable;

/**
 * Sends the optional notifications, driven entirely by the event surface.
 *
 * Deliberately a listener rather than a call inside the actions. Notification is a policy
 * decision an application makes, not a step in impersonating somebody — and keeping it
 * out here means a host can unsubscribe this listener and substitute its own without
 * touching the lifecycle.
 *
 * Every send is **degradable**. A mail server that is down must not prevent a support
 * engineer helping a customer, and it must certainly not prevent a *revocation* — an
 * alert that failed to send is a reported, recorded failure, not a reason to keep an
 * impersonation alive.
 */
final readonly class SendImpersonationNotifications
{
    public function __construct(
        private Settings $settings,
        private IdentityResolver $identities,
        private FailureReporter $reporter,
        private Events $events,
        private ApprovalStore $approvals,
    ) {}

    public function handleStarted(ImpersonationStarted $event): void
    {
        $this->notifyTarget($event->session);

        // Only full mode alerts on entry. An alert channel that fires on routine
        // read-only support work is one nobody reads.
        if ($event->session->mode->is('full')) {
            $this->alertSecurity($event->session, 'full_mode_enter');
        }
    }

    public function handleRevoked(ImpersonationRevoked $event): void
    {
        $this->alertSecurity($event->session, 'revoked');
    }

    public function handleExpired(ImpersonationExpired $event): void
    {
        $this->alertSecurity($event->session, 'expired');
    }

    // ── break-glass approvals ───────────────────────────────────────────────

    /**
     * Ask the approvers to decide.
     *
     * The request itself is re-read from the store rather than reconstructed from the event: the
     * event carries the impersonation request, while an approver needs the *approval* — its id,
     * its expiry and its state — and those live on the row.
     */
    public function handleApprovalRequested(ApprovalRequested $event): void
    {
        if (! $this->settings->bool('notifications.approvals.enabled', false)) {
            return;
        }

        $this->attempt('impersonator.notify.approval_requested', ['approval_id' => $event->approvalId], function () use ($event): void {
            $request = $this->approvals->find($event->approvalId);

            if ($request === null) {
                return;
            }

            $notification = new ApprovalRequestedNotification($request);

            foreach ($this->settings->stringList('notifications.approvals.mail') as $address) {
                Notification::route('mail', $address)->notify($notification);
            }

            foreach ($this->resolveApprovers($request) as $approver) {
                // The requester is skipped even if the resolver returns them. They cannot decide
                // their own request, so mailing them an approval prompt is noise that invites a
                // support ticket asking why the button does not work.
                if (! method_exists($approver, 'notify') || $this->isRequester($approver, $request)) {
                    continue;
                }

                $approver->notify($notification);
            }
        });
    }

    public function handleApprovalGranted(ApprovalGranted $event): void
    {
        $this->notifyRequester($event->approvalId);
    }

    public function handleApprovalDenied(ApprovalDenied $event): void
    {
        $this->notifyRequester($event->approvalId, $event->expired);
    }

    private function notifyRequester(string $approvalId, bool $expired = false): void
    {
        if (! $this->settings->bool('notifications.approvals.notify_requester', true)) {
            return;
        }

        $this->attempt('impersonator.notify.approval_decided', ['approval_id' => $approvalId], function () use ($approvalId, $expired): void {
            $request = $this->approvals->find($approvalId);

            if ($request === null) {
                return;
            }

            $requester = $this->identities->resolveActor($request->requester);

            if (! $requester instanceof Model || ! method_exists($requester, 'notify')) {
                $this->reporter->warn('Impersonator: approval requester cannot be notified.', [
                    'operation' => 'impersonator.notify.approval_decided',
                    'expected' => 'a notifiable requester model',
                    'actual' => $requester === null ? 'requester not resolvable' : 'model is not notifiable',
                    'decision' => 'tolerated',
                    'identifiers' => ['approval_id' => $approvalId],
                ]);

                return;
            }

            $requester->notify(new ApprovalDecided($request, $expired));
        });
    }

    /**
     * The application's approver list.
     *
     * A closure or invokable class name, because this package cannot find approvers itself — it is
     * duck-typed against an RBAC surface rather than depending on one, so it has no way to query
     * "everybody holding impersonator.approve". Anything the resolver returns that is not a model
     * is dropped here and anything unnotifiable is skipped at the call site, rather than either
     * being fatal: a misconfigured resolver must not stop the request being opened, since the row
     * is already written and the operator is already waiting.
     *
     * @return list<Model>
     */
    private function resolveApprovers(ApprovalRequest $request): array
    {
        $rule = $this->settings->raw('notifications.approvals.resolver');

        $callable = match (true) {
            $rule instanceof Closure => $rule,
            is_string($rule) && $rule !== '' && class_exists($rule) && method_exists($rule, '__invoke') => new $rule,
            is_callable($rule) => $rule,
            default => null,
        };

        if ($callable === null) {
            return [];
        }

        $resolved = $callable($request);

        if ($resolved instanceof Model) {
            $resolved = [$resolved];
        }

        if ($resolved instanceof Collection) {
            $resolved = $resolved->all();
        }

        if (! is_array($resolved)) {
            return [];
        }

        $approvers = [];

        foreach ($resolved as $approver) {
            if ($approver instanceof Model) {
                $approvers[] = $approver;
            }
        }

        return $approvers;
    }

    private function isRequester(Model $approver, ApprovalRequest $request): bool
    {
        return $this->identities->fromUser($approver)->is($request->requester);
    }

    private function notifyTarget(ImpersonationSession $session): void
    {
        if (! $this->settings->bool('notifications.notify_target', false)) {
            return;
        }

        $this->attempt('impersonator.notify.target', $this->sessionIds($session), function () use ($session): void {
            $target = $this->identities->toUser($session->target);

            // A model with no notification routing cannot be told anything; that is a
            // configuration gap worth a warning, not a failure.
            if (! $target instanceof Model || ! method_exists($target, 'notify')) {
                $this->reporter->warn('Impersonator: target cannot be notified.', [
                    'operation' => 'impersonator.notify.target',
                    'expected' => 'a notifiable target model',
                    'actual' => $target === null ? 'target not resolvable' : 'model is not notifiable',
                    'decision' => 'tolerated',
                    'identifiers' => ['audit_id' => $session->auditId],
                ]);

                return;
            }

            $notification = new TargetAccountAccessed($session);

            $delay = $this->settings->int('notifications.notify_target_delay', 0);

            // A delay is a real feature here rather than throttling: it lets disclosure
            // land after a short support interaction has finished, so the customer is not
            // emailed mid-conversation about the call they are currently on.
            $target->notify($delay > 0 ? $notification->delay(now()->addSeconds($delay)) : $notification);

            $this->events->dispatch(new TargetNotified($session, 'mail'));
        });
    }

    private function alertSecurity(ImpersonationSession $session, string $trigger): void
    {
        if (! $this->settings->bool('notifications.security_channel.enabled', false)) {
            return;
        }

        if (! in_array($trigger, $this->settings->stringList('notifications.security_channel.on'), true)) {
            return;
        }

        $this->attempt('impersonator.notify.security', $this->sessionIds($session), function () use ($session, $trigger): void {
            $notification = new ImpersonationSecurityAlert($session, $trigger);

            foreach ($this->settings->stringList('notifications.security_channel.mail') as $address) {
                Notification::route('mail', $address)->notify($notification);
            }

            $webhook = $this->settings->nullableString('notifications.security_channel.webhook');

            if ($webhook !== null) {
                // Routed through the notification system rather than an inline HTTP call
                // so it inherits queueing, retries and the application's own failure
                // handling instead of reimplementing all three.
                (new AnonymousNotifiable)
                    ->route('webhook', $webhook)
                    ->notify($notification);
            }
        });
    }

    /** @return array<string, string> */
    private function sessionIds(ImpersonationSession $session): array
    {
        return ['audit_id' => $session->auditId, 'mode' => $session->mode->name];
    }

    /**
     * Run a send, reporting and continuing on failure.
     *
     * The identifiers carry the audit or approval id — never the recipient address or the webhook
     * URL, since a failing notification path is exactly where a destination with an embedded token
     * tends to get logged.
     *
     * @param  array<string, string>  $identifiers
     */
    private function attempt(string $operation, array $identifiers, callable $send): void
    {
        try {
            $send();
        } catch (Throwable $failure) {
            $this->reporter->report(OperationFailed::from(
                operation: $operation,
                criticality: Criticality::Degradable,
                previous: $failure,
                expected: 'the impersonation notification to be dispatched',
                identifiers: $identifiers,
            ));
        }
    }
}
