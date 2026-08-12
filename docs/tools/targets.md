# Impersonatable targets

More than one user model, each with its own guard, display attribute and label.

Many applications have exactly one `User`. Plenty have several — staff and customers on separate
tables, a `Vendor` model on its own guard, a legacy `Member` table that has not been merged yet.

## The allowlist

The simple form, when one guard covers everything:

```php
'targets' => [
    'allowlist' => [
        'user' => App\Models\User::class,
    ],
],
```

The descriptive form, per type:

```php
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

| Key | Means |
|---|---|
| `model` | The Eloquent class |
| `guard` | The guard this type authenticates on; falls back to `guards.target` |
| `display_name` | The attribute shown in the banner; falls back to `banner.display_name` |
| `label` | Human name in a type picker; derived from the alias otherwise |

`guard` is the one that matters. Models on different guards cannot share a single global target
guard: authenticating a vendor against the customer provider would either fail confusingly or find
a different account with the same id.

## The alias is the durable identifier

The array key is a morph alias, and it is what the audit row stores — not the class name. That is
what keeps a trail resolvable after a class is renamed or moved, which over a few years is normal.
It is also what request input carries, so `target_type` is `vendor` rather than
`App\Models\Vendor`.

Lookups accept either form, because callers legitimately hold different ones: request input has the
alias, a Blade component has a model instance, and an old audit row may carry a fully-qualified
class name from before an alias existed.

## Registering at runtime

For a package that ships its own impersonatable model, without asking the host to edit config:

```php
// A service provider's boot()
Impersonator::registerTarget('vendor', Vendor::class, guard: 'vendor');
```

Runtime registrations override config entries of the same alias.

## Not a convenience — a control

This is the allowlist that stops arbitrary class injection. `target_type` is validated against it,
and a request naming anything else is refused **before the target is loaded**, so naming any
Eloquent model through a form field never gets it queried.

An empty allowlist therefore refuses everything. That is not a permissive default; it is a closed
door, and the doctor treats it as a failure rather than a warning because the refusal an operator
sees talks about the target type and reads like a bug in the caller.

Entries that are not installed Eloquent models are **dropped silently** — a typo narrows the
registry rather than crashing an unrelated request. The doctor compares the raw config against what
actually resolved and fails on the difference, since that is the only way to see it.

## The operator side is not the allowlist

The allowlist governs what may be *impersonated*. The operator's identity comes from the session,
not from request input, so an operator does not need to be allowlisted to impersonate somebody —
which matters when staff and customers are different models.

## Querying the registry

```php
$types = Impersonator::targets()->all();          // alias => ImpersonatableType
$type  = Impersonator::targets()->find('vendor');

$type->guardOr('web');
$type->label();

Impersonator::guardsFor('vendor');                // the Guards pair for this type
```

## Distinct guards end to end

Operator and target guards are independent throughout — the request records both, the audit row
stores both, and the adapter authenticates against the target's. A staff guard impersonating onto a
customer guard is a normal arrangement rather than a special case.

---

[← Docs index](../../README.md#documentation)
