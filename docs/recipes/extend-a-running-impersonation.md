# Extend a running impersonation

Keep a live impersonation past its deadline without leaving and re-entering.

```php
$outcome = Impersonator::extendSession();

if ($outcome->granted()) {
    // $outcome->session->expiresAt is the new deadline.
} else {
    // $outcome->grant->decision->code — extension_limit, extension_ceiling, …
}
```

The default banner already renders an **Extend** button when the rules allow it, so for most
installations there is nothing to build. The rest of this page is for a custom UI.

Note this is **not** `Impersonator::extend()`, which registers a driver — that name is inherited from
Laravel's Manager convention. The two are unrelated.

## Deciding whether to show a button

```php
$grant = Impersonator::canExtendSession();

$grant->granted();                // may they, right now?
$grant->decision->reason;         // why not, if not
```

Read-only and cheap: it evaluates the same rules without a lock or a write, so it is safe to call from
a view. It spends nothing.

Show the refusal rather than hiding the control. An operator who cannot extend needs to know *before*
the session ends under them, not at the moment it does.

## Wiring your own countdown

The banner emits the deadline in both forms, so a host application can attach a live countdown without
re-deriving it:

```html
<time datetime="2026-08-12T10:20:00+00:00" data-impersonator-expires-in="540">expires 10:20</time>
```

## From your own route

```php
Route::post('/support/extend', function () {
    $outcome = Impersonator::extendSession();

    abort_if($outcome->denied(), 403, (string) $outcome->grant->decision->reason);

    return back();
})->middleware('web');
```

Use POST. Extending changes state, so a GET route could be triggered by a prefetch or a pasted link —
silently keeping an impersonation alive that the operator had finished with.

If you add a route under a `read_only` impersonation, allowlist it by name, the way the package's own
is:

```php
'modes' => ['read_only' => ['allowed_routes' => ['impersonator.leave', 'impersonator.extend', 'support.extend']]],
```

## What you cannot do

**Extend somebody else's impersonation.** There is no audit-id parameter on any endpoint or method.
Prolonging another operator's access to an account on their behalf is not exposed — if their session
should continue, they can extend it themselves; if it should not, revoke it.

**Extend past the ceiling.** `limits.extension.max_total_duration` is absolute. When it is reached the
answer is to leave and enter again, which mints a new audit row — correctly, because that is a new
decision to access the account.

**Extend a revoked session.** Between an administrator marking a row and that session's next request,
the impersonation is both active and revoked. Extending inside that window is refused, or an operator
could buy time against their own kill switch.

Reference: [Extending a live impersonation](../configuration.md#extending-a-live-impersonation) and
[Timed impersonation](../security.md#timed-impersonation).

---

[← Docs index](../../README.md#documentation)
