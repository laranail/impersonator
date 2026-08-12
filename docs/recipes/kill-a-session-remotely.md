# Kill an impersonation remotely

End somebody else's impersonation, and make it take effect immediately.

```php
Impersonator::revoke($auditId, note: 'Escalated to security');
```

Two things are required for this to be immediate rather than merely recorded.

**A server-side session store:**

```env
SESSION_DRIVER=database
```

With `cookie` or `array` there is nothing to destroy from outside, so the revocation is recorded and
the session ends on its **next request** — for an idle tab, potentially a long time.

**The lifetime middleware on your routes:**

```php
// bootstrap/app.php
$middleware->appendToGroup('web', [
    \Simtabi\Laranail\Impersonator\Laravel\Middleware\GuardImpersonationLifetime::class,
]);
```

It enforces the revocation flag and also force-ends impersonations that outran
`limits.max_duration`. Without it, a recorded revocation is a note nobody reads.

Over the API, `meta.terminated` tells you which of the two happened:

```json
{ "meta": { "terminated": false, "message": "Revocation recorded. The session ends on its next request." } }
```

Revoking still works when `impersonator.enabled` is false — disabling the feature during an incident
must not remove the kill switch.

Reference: [Remote revocation](../tools/revocation.md).

---

[← Docs index](../../README.md#documentation)
