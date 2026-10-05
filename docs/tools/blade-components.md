# Blade components

Five drop-in components. Each renders nothing when it does not apply, so none needs a conditional.

That property is the design goal: a component you must wrap in `@if` is one somebody will forget to
wrap, and a forgotten conditional is a banner that silently fails to appear — or worse, an
impersonate button shown to somebody who cannot use it.

## The banner

```blade
<x-laranail-impersonator::banner />
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
<x-laranail-impersonator::impersonate-button :user="$customer" />

<x-laranail-impersonator::impersonate-button :user="$customer" mode="read_only" reason="Ticket #4182" />
```

Renders nothing when the current operator may not impersonate that account — it asks the
authorization policy, so it needs no `@can` wrapper and cannot drift from the rule that will be
applied on submit.

Note it asks "may this operator reach this account", not "is this submission complete". With
`reason.require` on, the button still renders for an operator who has not typed a reason yet;
otherwise the control needed to *supply* the reason would be hidden by the requirement to have one.

## The leave button

```blade
<x-laranail-impersonator::leave-button />
```

Renders only while impersonating. Leaving needs no permission, so this always works — including for
an operator whose access was revoked mid-session.

## The mode badge

```blade
<x-laranail-impersonator::badge />
```

The active mode, or nothing.

## Conditional content

```blade
<x-laranail-impersonator::when-impersonating>
    <p>You are viewing this account as support.</p>
</x-laranail-impersonator::when-impersonating>
```

## Names and deprecated aliases

Every component is registered under the package's Blade prefix, `laranail-impersonator`. Three
spellings resolve to each one:

| Scoped (use this) | Class-derived | Deprecated bare tag |
|---|---|---|
| `<x-laranail-impersonator::banner />` | `<x-laranail-impersonator::impersonation-banner />` | `<x-impersonation-banner />` |
| `<x-laranail-impersonator::impersonate-button />` | `<x-laranail-impersonator::impersonate-button />` | `<x-impersonate-button />` |
| `<x-laranail-impersonator::leave-button />` | `<x-laranail-impersonator::leave-impersonation-button />` | `<x-impersonation-leave-button />` |
| `<x-laranail-impersonator::badge />` | `<x-laranail-impersonator::impersonation-badge />` | `<x-impersonation-badge />` |
| `<x-laranail-impersonator::when-impersonating>` | `<x-laranail-impersonator::when-impersonating>` | `<x-when-impersonating>` |

The class-derived form resolves by **class name**, so it is not always the scoped string: the leave
button's class is `LeaveImpersonationButton`, so that tag reads `leave-impersonation-button`.

The bare tags are the names shipped before 0.1 was scoped. They still render exactly the same
component, but they are deprecated aliases: a template using one raises an `E_USER_DEPRECATED`
notice once, when Blade compiles it, and they may stop resolving no earlier than the next minor
after 0.1. A bare tag is a name in Blade's flat alias map, so another package or the application
registering `impersonation-banner` would silently replace this one.

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
disagree. `@impersonationBanner` is the directive form of `<x-laranail-impersonator::banner />`, for layouts
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
