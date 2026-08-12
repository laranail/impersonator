# Console commands

Seven Artisan commands. All named `laranail::impersonator.<command>`, per the laranail convention.

```bash
php artisan laranail::impersonator.doctor
php artisan laranail::impersonator.enter
php artisan laranail::impersonator.export-audit
php artisan laranail::impersonator.verify-audit
php artisan laranail::impersonator.prune-tokens
php artisan laranail::impersonator.prune-approvals
php artisan laranail::impersonator.scrub-identity
```

The `::` separator is not something Symfony Console accepts by default — its name validator rejects
the empty segment. The package writes the name past that validator through a small local trait, and
dispatch still works because Symfony resolves an exact name before its `:`-splitting lookup.

## `doctor`

```bash
php artisan laranail::impersonator.doctor
```

Diagnoses what is **silently** wrong. Every check exists because the failure it catches produces no
error: impersonation appears to work and the gap only surfaces during an incident or an audit. A
missing table throws on first use and needs no doctor.

Twenty-one checks: the master switch, boot health, tamper-evidence configuration, all five tables, the
target allowlist against what actually resolved, every configured guard, the driver, the adapter,
handoff URLs, the enter-plus-mode permission trap, the gate ability, whether a revocation can
genuinely end a session, the maximum duration, the extension ceiling, the approval setup and its
notifications and pruning, the API's auth stack, whether Octane's between-request resets are wired,
whether row-level security is enabled on the package tables, and other impersonation packages.

Four severities:

- **FAIL** — broken, or a control is not enforcing. Exits non-zero.
- **WARN** — works, but a control is weaker than the configuration implies.
- **OK** — checked and sound.
- **SKIP** — the precondition is absent, so there was nothing to check (approver notifications when
  approval is not required). Reported rather than hidden: "not applicable" and "not checked" are
  different statements, and only one of them is reassuring.

### The same checks in the family-wide doctor

Each check is a `DoctorCheck` registered into package-tools' shared `DoctorService`, so

```bash
php artisan laranail::package-tools.doctor
```

reports impersonation's findings under a `laranail/impersonator` group alongside every other laranail
package's. One list feeds both commands, so they cannot disagree.

This command stays because it is documented, referenced from the issue template, and — unlike the
shared runner — **exits non-zero on a failure**, which is what makes it usable as a CI gate.

Warnings do **not** fail the command. Several are legitimate choices — an unlimited duration on an
internal tool, tamper evidence off where the trail is not evidence — and a doctor that exits
non-zero for a deliberate decision is one teams stop running. Because only real failures exit
non-zero, it works as a CI gate.

It resolves the manager and the policy defensively, so it still reports on an install that is broken
enough that those cannot be built — which is the case it exists for.

## `enter`

```bash
php artisan laranail::impersonator.enter --target=9902 --as=42 --mode=read_only --reason="Ticket #4182"
```

Runs the **same** authorization stack as every other path — this is not a back door. Useful for
issuing a handoff token from a deploy shell, or for reproducing a refusal to see which rule fired.

With the token driver it prints the accept URL. That URL contains a live single-use token, so treat
the terminal output accordingly.

## `export-audit`

```bash
php artisan laranail::impersonator.export-audit 01k... --format=json
php artisan laranail::impersonator.export-audit 01k... --format=csv > incident-4182.csv
```

One impersonation and its full action trail, for a compliance request. Contains no credential hash
and no session id.

The same implementation the API uses, so an export produced by a support engineer and one pulled by
an auditor are byte-for-byte identical.

## `verify-audit`

```bash
php artisan laranail::impersonator.verify-audit
```

Walks the tamper-evidence chain and reports the first row where it breaks. Exits non-zero on a
break, so it can be scheduled rather than remembered.

Rows written before tamper evidence was switched on carry no digest and are skipped rather than
reported as breaks — otherwise the command would be useless on every existing installation.

A break means a row was altered, deleted, or inserted after the fact. The command cannot tell them
apart, which is fine: all three want the same response, and every row from that point on is
suspect.

## `prune-tokens`

```bash
php artisan laranail::impersonator.prune-tokens
```

Deletes expired, spent and revoked handoff tokens. Worth scheduling: the table takes a row per enter
on the token driver and is read on the hot path of every redemption, so it should stay small.

Nothing is lost. A spent token is not a credential, and the audit row is where the record of the
handoff lives.

## `prune-approvals`

```bash
php artisan laranail::impersonator.prune-approvals --limit=500
```

Marks timed-out break-glass requests expired and fires `ApprovalDenied(expired: true)`.

Not a security boundary — expiry is enforced when a permit is read, so a stale request is already
dead. What scheduling this adds is the **notification**: it is what tells a waiting operator that
nobody replied, which is the difference between them escalating and them assuming the system is
broken.

It expires rather than deletes. Removing the record that somebody asked for access to an account is
exactly what an auditor came to read; deletion is `model:prune`'s job, past
`approval.retention_days`.

## Scheduling

```php
// routes/console.php
use Illuminate\Support\Facades\Schedule;

Schedule::command('laranail::impersonator.prune-tokens')->hourly();
Schedule::command('laranail::impersonator.prune-approvals')->everyFiveMinutes();
Schedule::command('laranail::impersonator.verify-audit')->daily();
Schedule::command('model:prune')->daily();
```

`prune-approvals` runs often because its value is the notification, and a five-minute delay on
"nobody answered your break-glass request" is about the longest that is still useful.

## `php artisan about`

The package adds a panel:

```bash
php artisan about --only=impersonator
```

Reports the facts that change what impersonation *does* and are otherwise only discoverable by
reading config: the driver, the adapter, the default mode, the maximum duration, and whether
approval, tamper evidence and the API are on.

It never reports the audit hash key or a webhook URL. `about` output is what people paste into bug
reports.

## `scrub-identity`

```bash
php artisan laranail::impersonator.scrub-identity user:9902 --dry-run
```

GDPR erasure for a trail that is **deliberately** denormalised. `impersonator_label` and `target_label`
hold names as they were at the time, so a row stays readable after a rename or a deletion — a compliance
export that resolved names by joining live tables would report today's names against yesterday's
actions, or nothing at all once the row is gone.

That design is right, and it means an erasure request otherwise leaves the customer's name in the trail
with only time-based retention to clear it. This nulls the labels for one identity and leaves everything
else: the row, its ids, its timestamps and **the hash chain**, which covers the immutable opening facts
and not the labels — so `verify-audit` still passes afterwards, which a test asserts.

It does **not** delete rows. Erasure of personal data does not extend to erasing the record that a
support engineer accessed an account: that record is the controller's own evidence of processing, and
destroying it on request would remove the accountability the trail exists to provide.

The identity must be given as `type:id`. A bare id is ambiguous across models, and guessing the type is
how the wrong person's name gets erased.

---

[← Docs index](../../README.md#documentation)
