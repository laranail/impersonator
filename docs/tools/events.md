# Events

Fifteen events covering the whole lifecycle, including the refusals.

All in `Simtabi\Laranail\Impersonator\Core\Events` and all framework-free, so a listener can be
tested without booting anything.

## The lifecycle

| Event | Fires when |
|---|---|
| `ImpersonationRequested` | An attempt begins — **before** authorization |
| `ImpersonationRejected` | The authorization stack refused, with the `Decision` |
| `ImpersonationStarted` | The target is authenticated and the impersonation is live |
| `ImpersonationEnded` | It stopped, for any reason |
| `ImpersonationExtended` | An operator bought more time from inside a live impersonation |
| `ImpersonationExpired` | `max_duration` elapsed or the credential outlived its TTL |
| `ImpersonationRevoked` | An administrator ended it remotely |

`ImpersonationExtended` carries the session as it stands *after* the extension — so `expiresAt` is
the new deadline and `extensions` the new count — plus the grant, which reports how many seconds were
actually added. That is not always the configured amount: the last extension before the ceiling is
clamped rather than refused. Worth logging on its own, because the point of a short window is that
staying longer is a decision somebody made rather than a default nobody noticed.

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

## Every event is logged

`LogImpersonationLifecycle` handles **all fifteen**. OWASP's Logging Cheat Sheet asks for *all actions
by* privileged users and explicitly for *use of a break-glass account*; logging only the successful
starts and ends misses both, and the interesting lines are the refusals, the boundary probes and the
approvals.

Three properties worth knowing:

**Refusals log at a higher level.** A successful impersonation is routine; an operator repeatedly
attempting accounts they cannot reach is what an alert should fire on. So is `ModeViolationBlocked` — a
`read_only` session attempting a write is either an application bug or somebody working around the
boundary, and it is visible nowhere else.

**Every session-bearing line carries `audit_id`.** One value greps a whole impersonation: its start,
every mode violation inside it, each extension, its end. `HandoffTokenRejected` is the sole exception
and by construction — a rejected token has no audit row, so it is keyed on the IP and reason it
carries.

**Each reviewer's approval logs its own line.** Not just the final transition: a chain whose
intermediate approvals are invisible cannot answer "who signed off", which is the whole question an
audit of a four-eyes control asks.

`ImpersonationRequested` logs at `debug` — it fires before authorization, so on a busy install it is
the highest-volume line and says nothing on its own.

### A separable audit sink

```php
'logging' => [
    'channel'       => env('IMPERSONATOR_LOG_CHANNEL'),
    'audit_channel' => env('IMPERSONATOR_AUDIT_LOG_CHANNEL'),
],
```

`audit_channel` receives the tamper-relevant subset — started, ended, extended, revoked, expired, mode
violations, every approval decision — **in addition to** the ordinary channel, never instead of it. An
operator reading application logs during an incident should not have to know the interesting lines went
elsewhere.

Why it exists: ASVS 16.4.2/16.4.3 require that logs cannot be modified and are shipped off-box, and an
audit table writable by the application's own database user does not meet that. The HMAC chain gives
tamper **evidence**, not tamper **resistance** — only an external sink closes the gap. Point it at a
syslog, a SIEM, or anything append-only.

A channel name that does not resolve is ignored rather than fatal. The ordinary line is written before
the copy is attempted, so a typo costs a copy rather than a record.

## Replacing the package's own listeners

Logging and notifications are listeners rather than calls inside the actions, so you can unsubscribe
either and substitute your own without touching the lifecycle:

- `LogImpersonationLifecycle` — structured logs, refusals at a higher level
- `SendImpersonationNotifications` — the target notice, the security channel, the approval mails

Both are degradable: a failure is reported and execution continues. A mail server that is down must
not prevent a support engineer helping a customer, and it must certainly not prevent a revocation.

---

[← Docs index](../../README.md#documentation)
