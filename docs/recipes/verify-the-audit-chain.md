# Turn on and verify tamper evidence

Make an altered or deleted audit row detectable.

```env
IMPERSONATOR_TAMPER_EVIDENT=true
IMPERSONATOR_AUDIT_HASH_KEY="$(openssl rand -hex 32)"
```

```php
// routes/console.php
Schedule::command('laranail::impersonator.verify-audit')->daily();
```

```bash
php artisan laranail::impersonator.verify-audit
```

Exits non-zero at the first break and names the row. Every row from that point on is suspect.

**Keep the key outside the database.** A chain whose key sits alongside the rows protects nothing,
since anybody who can alter a row can recompute the digest. Turning tamper evidence on without a key
throws at boot rather than deriving one silently — a chain written with a key nobody recorded cannot
be verified later.

**Do not rotate the key** without re-verifying first: the chain can only be checked with the key it
was written with.

Rows written before you switched this on carry no digest and are skipped rather than reported as
breaks.

What this proves is that tampering *happened* — not who did it, and it does not prevent it.

Reference: [The audit trail](../tools/audit-trail.md).

---

[← Docs index](../../README.md#documentation)
