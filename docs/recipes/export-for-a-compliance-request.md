# Export an impersonation for a compliance request

Produce a document for "who accessed this customer's account, and what did they do".

Find the impersonations first:

```php
use Simtabi\Laranail\Impersonator\Laravel\Services\AuditService;

$rows = app(AuditService::class)->paginate([
    'target' => 'user:9902',
    'from'   => '2026-01-01',
    'to'     => '2026-08-31',
]);
```

Then export one:

```bash
php artisan laranail::impersonator.export-audit 01k... --format=csv > customer-9902.csv
```

Or over the API:

```http
GET /impersonator/api/v1/audits/01k.../export?format=json
```

The document holds the impersonation facts and its full action trail. It contains **no credential
hash and no session id** — a digest is still a verifier, and an export leaves the building.

The CSV is two sections rather than a flat table, because an impersonation and its actions are
one-to-many and flattening would repeat the session facts on every row.

The `impersonator_label` and `target_label` columns are denormalised at write time, so the export
stays readable after an account is renamed or deleted.

Reference: [The audit trail](../tools/audit-trail.md) · [Console commands](../tools/commands.md).

---

[← Docs index](../../README.md#documentation)
