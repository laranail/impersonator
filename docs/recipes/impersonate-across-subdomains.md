# Impersonate across domains

Hand an operator from an admin domain into an app domain with a single-use token.

```php
// config/impersonator.php
'driver' => 'token',
'urls'   => ['base_domain' => env('IMPERSONATOR_BASE_DOMAIN')],
```

```env
IMPERSONATOR_BASE_DOMAIN=app.example.com
```

```php
$outcome = Impersonator::enter($customer, driver: 'token');

if ($outcome->pending) {
    return redirect()->away($outcome->acceptUrl());
}
```

Check `pending` rather than assuming. A pending outcome means **nobody is impersonating yet** — the
operator must follow the URL, and treating it as live shows "now impersonating" for a session that
was never created.

Without `base_domain` the accept URL is built against the current host, which for a cross-domain
handoff is the wrong host. The doctor warns about exactly this.

The token lives 60 seconds, is single-use, and is re-authorized on redemption — a role withdrawn
between issuing the link and following it refuses the handoff.

Reference: [Drivers](../tools/drivers.md) · [The security model](../security.md).

---

[← Docs index](../../README.md#documentation)
