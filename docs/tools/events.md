# Events

Fourteen events covering the whole lifecycle, including the refusals.

All in `Simtabi\Laranail\Impersonator\Core\Events` and all framework-free, so a listener can be
tested without booting anything.

## The lifecycle

| Event | Fires when |
|---|---|
| `ImpersonationRequested` | An attempt begins — **before** authorization |
| `ImpersonationRejected` | The authorization stack refused, with the `Decision` |
| `ImpersonationStarted` | The target is authenticated and the impersonation is live |
| `ImpersonationEnded` | It stopped, for any reason |
| `ImpersonationExpired` | `max_duration` elapsed or the credential outlived its TTL |
| `ImpersonationRevoked` | An administrator ended it remotely |

`ImpersonationRequested` fires for refused attempts too, which is the point: a listener counting
attempts needs the true rate, not only the successes. `ImpersonationRejected` is emitted **before**
the exception is thrown, so a refusal stays observable even when the caller catches it and renders
its own response.

## Handoff tokens

| Event | Fires when |
|---|---|
| `HandoffTokenIssued` | A single-use token was minted |
| `HandoffTokenRedeemed` | One was accepted |
| `HandoffTokenRejected` | One was refused — carries the reason and the IP |

`HandoffTokenRejected` carries the *real* reason (unknown, expired, spent, revoked) because it goes
to your log. The client is told nothing that distinguishes them: telling somebody probing the accept
route that a token merely expired tells them the token was real.

## Modes

| Event | Fires when |
|---|---|
| `ModeViolationBlocked` | An impersonated session attempted something its mode forbids |

The signal worth alerting on. A read-only session attempting writes is either a bug in your
application or an operator working around the boundary.

## Approvals

| Event | Fires when |
|---|---|
| `ApprovalRequested` | A break-glass request was opened |
| `ApprovalGranted` | A second operator approved it |
| `ApprovalDenied` | Refused, or expired unanswered (`expired: true`) |

Nobody is impersonating anything when `ApprovalRequested` fires. A listener that provisioned access
here would defeat the control it is listening to.

## Notifications

| Event | Fires when |
|---|---|
| `TargetNotified` | The target was told their account was accessed |

## Listening

```php
// A service provider's boot()
Event::listen(ImpersonationStarted::class, function (ImpersonationStarted $event): void {
    $event->session->auditId;
    $event->session->impersonator;
    $event->session->target;
    $event->session->mode->name;
    $event->session->reason;
});
```

```php
Event::listen(ModeViolationBlocked::class, function (ModeViolationBlocked $event): void {
    Alert::raise('Impersonation mode violation', $event->session->auditId);
});
```

## What events never carry

No token plaintext, no credential secret, no credential hash, no session id. An event payload ends
up in a queue, a log, and sometimes a third-party error tracker — every one a place a credential
must not reach.

## Replacing the package's own listeners

Logging and notifications are listeners rather than calls inside the actions, so you can unsubscribe
either and substitute your own without touching the lifecycle:

- `LogImpersonationLifecycle` — structured logs, refusals at a higher level
- `SendImpersonationNotifications` — the target notice, the security channel, the approval mails

Both are degradable: a failure is reported and execution continues. A mail server that is down must
not prevent a support engineer helping a customer, and it must certainly not prevent a revocation.

---

[← Docs index](../../README.md#documentation)
