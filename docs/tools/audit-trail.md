# The audit trail

Two levels of record: one row per impersonation, one row per action taken during it.

The feature that answers the question a compliance review actually asks — not "can staff
impersonate users" but "who accessed this account, when, why, and what did they do".

## The two tables

| Table | Grain |
|---|---|
| `impersonator_audits` | One row per impersonation |
| `impersonator_audit_events` | One row per action within an impersonation |

## The session-level row

Written **before** authentication, in every driver. It reads backwards and it is deliberate: if
authentication fails halfway, the attempt is still on record. A row written only after a successful
login records only the impersonations that worked, which is the opposite of what an audit trail is
for.

Holds the operator and target identities, the mode, both guards, the driver and adapter, the
tenant, the reason, when it started, when and how it ended, the expiry, and the revocation
timestamp.

Two columns exist to survive time: `impersonator_label` and `target_label` are **denormalised** at
write time, so a row stays readable after the account is renamed or deleted. A trail that reads
"user 4813 accessed user 9902" a year later is not a trail anybody can use.

## The action-level trail

Recorded by the `RecordImpersonationTrail` middleware:

```php
$middleware->appendToGroup('web', [
    \Simtabi\Laranail\Impersonator\Laravel\Middleware\RecordImpersonationTrail::class,
]);
```

Each row holds the method, path, route name, response status, duration and timestamp.

**Payloads are not recorded by default:**

```php
'trail' => [
    'record_payloads' => false,
    'redact' => ['password', 'token', 'secret', 'authorization', '...'],
    'ignore_paths' => ['telescope*', 'horizon*', '_debugbar*'],
],
```

When on, every payload is redacted recursively first. Redaction is a filter, not a guarantee — a
field nobody thought to name still gets through — which is exactly why it is off. Turning it on is
a decision about what you are willing to store.

## Reading it

```php
use Simtabi\Laranail\Impersonator\Laravel\Services\AuditService;

$audits = app(AuditService::class);

$page = $audits->paginate([
    'impersonator' => 'user:42',      // or a bare id
    'target'       => 'user:9902',
    'mode'         => 'full',
    'driver'       => 'session',
    'ended_by'     => 'revoked',
    'active'       => true,
    'tenant'       => 'acme',
    'from'         => '2026-08-01',
    'to'           => '2026-08-31',
]);

$trail = $audits->trail($auditId, limit: 100);
$count = $audits->trailCount($auditId);
```

Every filter is applied in SQL rather than in PHP: an audit table is the one table that only grows,
and a year-old trail will not fit in memory. Date filters bound `started_at` rather than
`created_at`, because "what happened last Tuesday" means when the impersonation ran.

`AuditService` is separate from `AuditStore` on purpose. The store is the write path plus the
narrow lookups the middleware needs on every request; this is the read path an auditor uses. They
have opposite constraints, and merging them would drag reporting concerns onto the hot path.

## What is never in it

No credential hash, and no session id — not in a listing, a detail view, an export, or a log. A
digest is still a verifier: a holder can confirm a guessed token against it.

This is structural rather than remembered. `ImpersonationSession::toArray()` is the safe
projection, and every consumer — the API resources, the exporter, the notifications — goes through
it rather than assembling fields by hand.

## Causer attribution

```php
'causer' => ['resolver' => null],
```

Defaults to the **impersonator**, since they are the person who actually acted. Supply a closure or
invokable class to change it — some applications want the target recorded for their own activity
log, so the two notions of "who did this" stay separate.

Integrates with `spatie/laravel-activitylog` when installed, without depending on it.

## Tamper evidence

```php
'audit' => [
    'tamper_evident' => true,
    'hash_key' => env('IMPERSONATOR_AUDIT_HASH_KEY'),
],
```

Each row carries a keyed HMAC over the previous row's digest plus this row's immutable opening
facts. It deliberately does **not** cover `ended_at` or `revoked_at`: those are written after the
digest, and a chain over them would break on every normal close.

Verify it:

```bash
php artisan laranail::impersonator.verify-audit
```

Exits non-zero at the first break and names the row. A break means one of three things — a row
altered, deleted, or inserted after the fact — and the command cannot tell them apart, which is
fine because all three want the same response.

**What this does and does not prove.** The key lives in config, outside the database, and that is
the whole mechanism: a chain whose key sits alongside the rows protects nothing, since anybody who
can alter a row can recompute the digest. The chain proves tampering *happened*. It does not
prevent it, and it does not say who. Turning it on without a key throws at boot rather than
silently deriving one, because a chain written with a key nobody recorded cannot be verified later.

## Export

```bash
php artisan laranail::impersonator.export-audit <audit-id> --format=json
php artisan laranail::impersonator.export-audit <audit-id> --format=csv
```

Or `GET /audits/{audit}/export` on the [REST API](rest-api.md).

One implementation shared by both, so an export produced by a support engineer and one pulled by an
auditor are byte-for-byte identical — two exporters would eventually disagree, and the
disagreement would surface during an audit.

The CSV is two sections rather than a flat table: an impersonation and its actions are
one-to-many, and flattening would repeat the session facts on every row.

## Retention

```php
'audit' => ['retention_days' => 365],
```

Enforced through `MassPrunable`, so `php artisan model:prune` does the work without loading a long
history into memory. A null retention prunes **nothing** — the query matches nothing rather than
everything, because getting that backwards would delete the entire audit trail.

---

[← Docs index](../../README.md#documentation)
