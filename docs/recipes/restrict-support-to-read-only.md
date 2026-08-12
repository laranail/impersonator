# Restrict support staff to read-only

Pin junior staff to `read_only` while senior operators may choose `full`.

Requires spatie/laravel-permission; the RBAC layer activates itself when it is installed.

```php
// A seeder
Permission::create(['name' => 'impersonator.enter']);
Permission::create(['name' => 'impersonator.mode.read_only']);
Permission::create(['name' => 'impersonator.mode.full']);

Role::findByName('support')->givePermissionTo([
    'impersonator.enter',
    'impersonator.mode.read_only',
]);

Role::findByName('admin')->givePermissionTo([
    'impersonator.enter',
    'impersonator.mode.read_only',
    'impersonator.mode.full',
]);
```

```php
// config/impersonator.php
'default_mode' => 'read_only',
```

Then enforce it — a mode that is selectable but not applied reports a restriction it is not
enforcing:

```php
// bootstrap/app.php
'routes' => ['auto_append_to_groups' => ['web']],
```

Grant both permissions, not just `impersonator.enter`. An operator holding only the first can
impersonate nothing at all, and the refusal names the *mode* — which sends them asking for the wrong
permission. Run the doctor to confirm.

Reference: [Impersonation modes](../tools/modes.md) · [Authorization](../tools/authorization.md).

---

[← Docs index](../../README.md#documentation)
