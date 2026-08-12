# Remote revocation

The kill switch: end an impersonation you do not own.

```php
Impersonator::revoke($auditId, note: 'Escalated to security');
```

Requires `impersonator.revoke` — its own permission, because revoking is a de-escalation and
warrants separate authorisation from entering.

## Immediate, or recorded?

The distinction matters operationally, and the package tells you which happened rather than
implying the stronger guarantee.

| Credential | Effect |
|---|---|
| Sanctum / Passport token | **Immediate** — the token is deleted |
| Session on `database`, `redis`, `file` | **Immediate** — the session is destroyed out of band |
| Session on `cookie`, `array` | **Recorded** — ends on the session's next request |
| JWT | **Recorded** — a JWT is self-contained; blacklist it separately |

Out-of-band session termination goes through `SessionHandlerInterface::destroy()`, which is why it
works across every server-side store rather than only the database driver.

```php
'session' => ['destroy_on_revoke' => true],
```

For `cookie` and `array` there is no server-side record to reach into, so the revocation is marked
on the audit row and `GuardImpersonationLifetime` ends the session on its next request. For an
idle tab that could be a while — which is exactly why the doctor warns about those two drivers.

## Both halves are required

The middleware is not optional:

```php
$middleware->appendToGroup('web', [
    \Simtabi\Laranail\Impersonator\Laravel\Middleware\GuardImpersonationLifetime::class,
]);
```

It is what enforces the revocation flag, and also what force-ends an impersonation that outran
`limits.max_duration`. Without it a recorded revocation is a note nobody reads.

## Over the API

```http
POST /impersonator/api/v1/impersonations/{audit}/revoke
```

```json
{
  "data": { "revoked_at": "2026-08-12T11:04:00+00:00", "active": true },
  "meta": { "terminated": false, "message": "Revocation recorded. The session ends on its next request." }
}
```

`active` and `revoked_at` can both be set, and that is not a contradiction: revocation is recorded
first, and the session ends on its next request.

## Revocation survives the master switch

```php
'enabled' => false,
```

Turning impersonation off refuses every *enter* and leaves revocation working. Disabling the
feature during an incident must not also remove the ability to kill the sessions already running —
that would be the worst possible moment to lose the kill switch.

## Leaving is always available

`Impersonator::leave()` consults no policy at all. Leaving only ever de-escalates, and an operator
whose access was revoked mid-session must still be able to stop being somebody else. A permission
check on the exit is a design that can trap a person inside a customer's account.

## Also ends an impersonation

| Cause | `ended_by` |
|---|---|
| The operator left | `left` |
| `max_duration` elapsed, or the credential expired | `expired` |
| An administrator revoked it | `revoked` |
| The backing session vanished | `session_lost` |

`session_lost` is recorded on the next reconciliation rather than left dangling as active, because
a row that stays open forever reads as an ongoing breach.

---

[← Docs index](../../README.md#documentation)
