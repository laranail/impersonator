# Impersonate a second user model

Add a `Vendor` model on its own guard, alongside `User`.

```php
// config/impersonator.php
'targets' => [
    'allowlist' => [
        'user' => App\Models\User::class,

        'vendor' => [
            'model'        => App\Models\Vendor::class,
            'guard'        => 'vendor',
            'display_name' => 'company_name',
            'label'        => 'Vendor account',
        ],
    ],
],
```

```php
Impersonator::enter($vendor);      // authenticates on the `vendor` guard
```

`guard` is the setting that matters. Models on different guards cannot share one global target
guard: authenticating a vendor against the customer provider would either fail confusingly or find
a different account with the same id.

From a package, register at runtime instead of asking the host to edit config:

```php
Impersonator::registerTarget('vendor', Vendor::class, guard: 'vendor');
```

The alias — `vendor`, not the class name — is what request input carries and what the audit row
stores, so the trail stays resolvable after a class is renamed.

Reference: [Impersonatable targets](../tools/targets.md).

---

[← Docs index](../../README.md#documentation)
