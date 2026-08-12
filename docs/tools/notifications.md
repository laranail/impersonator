# Notifications

Three optional notification paths: the target's disclosure notice, a security channel, and the
break-glass approval mails.

All off by default — enabling any of them changes what your users receive.

## Telling the target

```php
'notifications' => [
    'notify_target'       => true,
    'notify_target_delay' => 300,
],
```

A transparency and GDPR posture choice rather than a security control. The customer learns their
account was accessed.

The delay is a real feature, not throttling: it lets the disclosure land **after** a short support
interaction has finished, so the customer is not emailed mid-conversation about the call they are
currently on.

The notice deliberately does **not** name the operator. The audience is the account holder, and
"a member of our support team accessed your account" is the useful sentence; an individual staff
name invites a customer to contact them directly and adds nothing they can act on.

A target model without notification routing produces a **warning**, not a failure — that is a
configuration gap worth surfacing rather than a reason to refuse the impersonation.

## The security channel

```php
'notifications' => [
    'security_channel' => [
        'enabled' => true,
        'mail'    => ['security@example.com'],
        'webhook' => env('IMPERSONATOR_SECURITY_WEBHOOK'),
        'on'      => ['full_mode_enter', 'revoked'],
    ],
],
```

| Trigger | Fires on |
|---|---|
| `full_mode_enter` | Somebody entered an account with full access |
| `revoked` | An administrator ended an impersonation |
| `expired` | One was force-ended at its time limit |

Routine `read_only` support work does **not** alert, and that is the whole design of the default: an
alert channel that fires on everything is one nobody reads, and a channel nobody reads is worse than
none because it looks like coverage.

Unlike the target notice this **does** name the operator. The audience is the security team, and an
alert that omits who did it is not actionable.

The webhook is routed through Laravel's notification system rather than an inline HTTP call, so it
inherits queueing, retries and your own failure handling instead of reimplementing all three.

## Approval mails

```php
'notifications' => [
    'approvals' => [
        'enabled'          => true,
        'mail'             => ['security@example.com'],
        'resolver'         => fn ($request) => User::role('approver')->get(),
        'notify_requester' => true,
    ],
],
```

Approvers have to be told a request is waiting. A queue nobody is notified about gets checked after
the incident is over, by which point the operator has asked a colleague to work around the control.

The package cannot find your approvers itself — it duck-types an RBAC surface rather than depending
on one, so it cannot query "everybody holding `impersonator.approve`". Supply a resolver returning
notifiables, or list plain addresses, or both.

The requester is filtered out of the resolver's result even if it returns them: they cannot decide
their own request, so mailing them an approval prompt is noise that turns into a support ticket.

**No approval link and no credential** is in the mail. The decision is made through your own
authenticated surface; a one-click approve token would move the four-eyes control into an inbox.

`notify_requester` covers all three outcomes including expiry, because an operator left wondering
whether they were refused or simply never answered will route around the control.

## Every send is degradable

A failed notification is reported to `FailureReport` and execution continues. A mail server that is
down must not prevent a support engineer helping a customer, and it must certainly not prevent a
*revocation* — an alert that failed to send is a recorded failure, not a reason to keep an
impersonation alive.

The reported identifiers carry the audit or approval id and never the recipient address or webhook
URL, since a failing notification path is exactly where a destination with an embedded token tends
to get logged.

## Replacing them

`SendImpersonationNotifications` is a plain listener. Unsubscribe it and register your own against
the [events](events.md) — notification is an application policy, not a step in impersonating
somebody.

## The notification classes

| Class | Sent to |
|---|---|
| `TargetAccountAccessed` | The impersonated account holder |
| `ImpersonationSecurityAlert` | The security channel |
| `ApprovalRequestedNotification` | The approvers |
| `ApprovalDecided` | The requester |

All queueable, all with `toMail()` and `toArray()`. The array form is the audit-safe projection —
no credential, no session id — because an alert gets forwarded, pasted into chat, and archived in
places the audit table is not.

---

[← Docs index](../../README.md#documentation)
