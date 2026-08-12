# Require approval for full access

Make `full` impersonation need a second operator, and leave `read_only` alone.

```php
// config/impersonator.php
'approval' => [
    'require'      => true,
    'ttl'          => 15,
    'except_modes' => ['read_only'],
],

'notifications' => [
    'approvals' => [
        'enabled'  => true,
        'resolver' => fn () => User::role('security')->get(),
    ],
],
```

```php
// routes/console.php
Schedule::command('laranail::impersonator.prune-approvals')->everyFiveMinutes();
```

Handle the pause in your controller:

```php
try {
    $outcome = Impersonator::enter($customer, mode: 'full', reason: $request->reason);
} catch (ApprovalRequired $e) {
    return back()->with('status', "Awaiting approval (request {$e->approvalId}).");
}
```

The requester retries the same call once it is granted. Keep `read_only` exempt: requiring a second
person for routine support work trains everyone to approve reflexively, which is how the control
becomes a rubber stamp.

Schedule the sweep or an operator whose request went unanswered is never told nobody replied.

Reference: [Break-glass approvals](../tools/approvals.md).

---

[← Docs index](../../README.md#documentation)
