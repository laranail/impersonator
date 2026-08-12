# Scope rows correctly under PostgreSQL RLS

Make row-level security follow the impersonated account rather than the operator.

## The bug this avoids

If your RLS context is set from `auth()->id()`, an impersonated session sends the **operator's** id to
the database. The policy then returns the operator's rows while the application claims to be the
customer — the exact inversion impersonation exists to avoid, and it looks like working software.

```php
// Wrong while impersonating: this is the support engineer, not the customer.
DB::select('select set_config(?, ?, true)', ['app.current_user_id', (string) auth()->id()]);
```

## The fix

One line. Read the effective identity instead:

```php
use Simtabi\Laranail\Impersonator\Laravel\Support\RlsContext;

$identity = app(RlsContext::class)->effective();   // the target while impersonating

DB::select('select set_config(?, ?, true)', ['app.current_user_id', (string) $identity?->id]);
```

`effective()` returns the target during an impersonation and the authenticated user otherwise, so the
same call is correct in both cases. It returns null when nobody is authenticated at all — a queue worker
or a console command — and you must handle that rather than being handed a fabricated identity.

## Optional: let policies see the impersonation

```php
'rls' => ['enabled' => true],
```

```php
Route::middleware(['web', 'impersonator.rls'])->group(/* … */);
```

This publishes the context as transaction-scoped GUCs — `app.impersonated_user_id`,
`app.impersonator_id`, `app.impersonation_mode`, `app.impersonation_audit_id` — so a policy can refuse
writes under `read_only` at the **database** level:

```sql
create policy no_writes_while_read_only on invoices
    for update using (current_setting('app.impersonation_mode', true) is distinct from 'read_only');
```

That is defence in depth, not a replacement. The PHP mode guard stays primary, because a write blocked
only by a policy cannot be reported as a `ModeViolationBlocked` event — so the boundary probe, which is
the most security-relevant signal here, becomes invisible.

## Two rules the implementation follows, and you should too

**Use `select set_config(?, ?, true)` with bindings — never `SET LOCAL app.x = '…'`.** `SET` cannot take
a bind parameter, so any implementation reaching for it has to concatenate the value, on a path that
handles identity. That is an SQL injection hole.

**Pass `true` for the third argument: transaction scope.** With PgBouncer in transaction mode a
session-scoped GUC **leaks to the next client that receives the connection** — a data breach, and the
most-cited RLS footgun there is. The cost is that transaction scope does not survive a request, which is
why the middleware sets it per transaction rather than once.

## Keep the package's own tables out of it

If a policy hides an audit row, the HMAC chain breaks in a way that looks like tampering: each row's
digest covers its predecessor's, so a hidden predecessor makes `verify-audit` report a break that never
happened, and an export return an empty trail. `FORCE ROW LEVEL SECURITY` is worse — it applies to the
table owner too.

Exempt the five package tables, or policy them explicitly for the application's database user. They hold
the record *about* access rather than tenant data, so scoping them by tenant answers the wrong question.

`php artisan laranail::impersonator.doctor` fails when RLS is enabled on any of them.

---

[← Docs index](../../README.md#documentation)
