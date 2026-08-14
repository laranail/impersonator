# Blade components

Five drop-in components. Each renders nothing when it does not apply, so none needs a conditional.

That property is the design goal: a component you must wrap in `@if` is one somebody will forget to
wrap, and a forgotten conditional is a banner that silently fails to appear — or worse, an
impersonate button shown to somebody who cannot use it.

## The banner

```blade
<x-impersonation-banner />
```

Place it once in a layout, unconditionally. It renders nothing when nobody is impersonating.

```php
'banner' => [
    'enabled'      => true,
    'position'     => 'top',      // top | bottom
    'display_name' => 'name',
    'show_mode'    => true,
],
```

Restyle it by publishing the views:

```bash
php artisan vendor:publish --tag=impersonator-views
```

## The impersonate button

```blade
<x-impersonate-button :user="$customer" />

<x-impersonate-button :user="$customer" mode="read_only" reason="Ticket #4182" />
```

Renders nothing when the current operator may not impersonate that account — it asks the
authorization policy, so it needs no `@can` wrapper and cannot drift from the rule that will be
applied on submit.

Note it asks "may this operator reach this account", not "is this submission complete". With
`reason.require` on, the button still renders for an operator who has not typed a reason yet;
otherwise the control needed to *supply* the reason would be hidden by the requirement to have one.

## The leave button

```blade
<x-impersonation-leave-button />
```

Renders only while impersonating. Leaving needs no permission, so this always works — including for
an operator whose access was revoked mid-session.

## The mode badge

```blade
<x-impersonation-badge />
```

The active mode, or nothing.

## Conditional content

```blade
<x-when-impersonating>
    <p>You are viewing this account as support.</p>
</x-when-impersonating>
```

## Namespaced aliases

Every component is also available namespaced, for teams that prefer it or already own the short
names. The namespaced form resolves by **class name**, so it is not always the same string as the
alias:

| Alias | Namespaced |
|---|---|
| `<x-impersonation-banner />` | `<x-laranail-impersonator::impersonation-banner />` |
| `<x-impersonate-button />` | `<x-laranail-impersonator::impersonate-button />` |
| `<x-impersonation-leave-button />` | `<x-laranail-impersonator::leave-impersonation-button />` |
| `<x-impersonation-badge />` | `<x-laranail-impersonator::impersonation-badge />` |
| `<x-when-impersonating>` | `<x-laranail-impersonator::when-impersonating>` |

Note the leave button: its class is `LeaveImpersonationButton`, so the namespaced tag reads
`leave-impersonation-button` while the alias reads `impersonation-leave-button`. The alias is the
one to prefer.

## Blade directives

Four directives, registered through `Blade::if` — which means each also gets an `@unless…` and an
`@else…` form for free.

```blade
@impersonating
    <span>Impersonating {{ Impersonator::current()?->target->label }}</span>
@else
    <span>Signed in as yourself</span>
@endimpersonating

@unlessimpersonating
    <span>Signed in as yourself</span>
@endimpersonating

@impersonationMode('read_only')
    <span>Read-only — changes are blocked.</span>
@endimpersonationMode

@canImpersonate($customer)
    <a href="...">Impersonate</a>
@endcanImpersonate

@impersonationBanner
```

`@canImpersonate` runs the same policy the action runs, so a hidden button and a 403 can never
disagree. `@impersonationBanner` is the directive form of `<x-impersonation-banner />`, for layouts
that are not using components.

## The route macro

```php
Route::impersonate();     // registers the package's routes wherever you want them
```

Sugar for applications that disable `routes.enabled` and place the routes inside their own group —
under an admin prefix, behind extra middleware, or on a specific domain.

## Reading state directly

For a UI the components do not cover:

```php
Impersonator::isImpersonating();
Impersonator::current();                        // ImpersonationSession|null
Impersonator::currentImpersonatorOrNull();      // the operator's model
Impersonator::canImpersonate($customer, 'full');
```

---

[← Docs index](../../README.md#documentation)
