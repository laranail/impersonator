# Impersonate an API client

Hand a mobile or SPA client a short-lived, scoped token for the target instead of a session.

```php
// config/impersonator.php
'adapter'  => 'sanctum',
'adapters' => [
    'sanctum' => ['ttl' => 10, 'abilities' => ['read']],
],
```

```php
$outcome = Impersonator::enter($customer, mode: 'read_only', adapter: 'sanctum');

return response()->json([
    'token'      => $outcome->credential->secret(),
    'expires_at' => $outcome->credential->expiresAt,
]);
```

The secret is readable **exactly once**, from the issuing call. Only a SHA-256 digest is stored, and
no endpoint, export or log ever returns the digest.

The target model does not need Sanctum's `HasApiTokens` trait — the adapter writes through Sanctum's
own token model, which matters because Laravel's default `User` does not declare Sanctum's interface.

Two independent narrowings apply and both are worth setting: `abilities` scopes the token, and
`mode` bounds what the impersonated session may do regardless of the token's abilities.

Revoking deletes the token, so it takes effect immediately — unlike `jwt`, where nothing
server-side exists to delete.

Reference: [Auth adapters](../tools/auth-adapters.md) · [Drivers](../tools/drivers.md).

---

[← Docs index](../../README.md#documentation)
