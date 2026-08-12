# Auth adapters

Four adapters decide *how* the target is authenticated: `session`, `sanctum`, `passport`, `jwt`.

The second axis of the design. Any adapter composes with any [driver](drivers.md), which is what
makes "issue a mobile client a read-only token for this customer, expiring in ten minutes" a
configuration rather than a fork.

```php
'adapter' => env('IMPERSONATOR_ADAPTER', 'session'),
```

Or per call: `Impersonator::enter($user, adapter: 'sanctum')`.

## `session`

The default. Logs the target into the configured guard.

- Regenerates the session id **before** the switch, and again on leave.
- Logs in without firing login events, so the target's "new sign-in" listeners do not run.
- Never issues remember-me — a persistent cookie would outlive the audit row that bounds it.
- Revocation destroys the session out of band where the store allows it.

## `sanctum`

Issues a personal access token for the target and returns it once.

```php
$outcome = Impersonator::enter($customer, adapter: 'sanctum');

$outcome->credential->secret();     // readable exactly once
```

```php
'adapters' => [
    'sanctum' => ['ability' => 'impersonated', 'expires_after' => 15],
],
```

The token carries a single named `ability` rather than `*`, so a resource server can recognise an
impersonated call without knowing this package exists, and `expires_after` (minutes) is independent
of the application's own Sanctum expiration. The token is written
through Sanctum's own `personalAccessTokenModel()`, so the target model does **not** need the
`HasApiTokens` trait — which matters because Laravel's default `User` does not declare Sanctum's
interface.

Revocation deletes the token, so it is immediate.

## `passport`

Issues an OAuth access token.

```php
'adapters' => [
    'passport' => ['scope' => 'impersonated', 'expires_after' => 15],
],
```

Requires the target to implement Passport's `OAuthenticatable`, a personal access client to exist,
and a `passport` guard to be configured. A refresh token is **never** issued: a refresh token
would let the impersonation outlive its own audit row.

Named scopes are registered if absent, so a scope you configure here does not have to be declared
elsewhere too.

## `jwt`

For `tymon/jwt-auth`. Mints a token carrying impersonation claims.

| Claim | Holds |
|---|---|
| `imp_by` | The operator's identity |
| `imp_audit` | The audit row id |
| `imp_mode` | The mode |

The claims are what let a resource server see that a request is impersonated and by whom, without
a database lookup.

**`revoke()` returns false honestly.** A JWT is self-contained: there is nothing server-side to
delete, so a revocation cannot invalidate an already-issued token. Call `blacklist()` separately
if you run the blacklist, and keep the TTL short. Reporting success here would be a lie that
matters.

## Which credential came back

```php
$outcome->credential?->type;        // CredentialType enum
$outcome->credential?->secret();    // once, and only from the issuing call
$outcome->credential?->expiresAt;
```

Only a SHA-256 digest is stored, and **no endpoint, listing, export or log ever returns the
digest** — a digest is still a verifier, so a holder can confirm a guessed token against it.

## Writing your own

```php
Impersonator::extendAdapter('opaque', fn ($app) => new OpaqueTokenAdapter(/* ... */));
```

The contract is three methods: `authenticate`, `release`, `revoke`. Return a `Credential` from
`authenticate` and be honest in `revoke` about whether the credential could actually be
invalidated.

---

[← Docs index](../../README.md#documentation)
