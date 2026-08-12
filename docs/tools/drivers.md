# Drivers

Three drivers decide *how* an impersonation is established: `session`, `token`, `tenancy`.

A driver is one axis of the design. The other is the [auth adapter](auth-adapters.md), which
decides how the target is actually authenticated. They compose: any driver works with any adapter.

## Choosing one

| Driver | Use when |
|---|---|
| `session` | Operator and target share a domain. The common case. |
| `token` | The target lives on a different domain, or you are handing a credential to a client. |
| `tenancy` | Multi-tenant, and the target lives inside a tenant. |

```php
'driver' => env('IMPERSONATOR_DRIVER', 'session'),
```

Or per call: `Impersonator::enter($user, driver: 'token')`.

## `session`

Switches the authenticated user in place.

```php
Impersonator::enter($customer);
```

The session id is regenerated before the switch, the target is logged in without firing login
events, and the operator's identity is kept server-side. Returns a **started** outcome: the
impersonation is live on this request.

## `token`

Issues a single-use handoff token and returns an accept URL. **Nobody is impersonating yet** —
the operator must follow the URL.

```php
$outcome = Impersonator::enter($customer, driver: 'token');

$outcome->pending;        // true
$outcome->acceptUrl();    // https://app.example.com/impersonator/accept/<token>
```

Treating a pending outcome as live is how a UI ends up showing "now impersonating" for a session
that was never created, which is why the two shapes are distinct types rather than a flag you
might forget to read.

Set the destination host or the URL is built against the current one:

```php
'urls' => ['base_domain' => env('IMPERSONATOR_BASE_DOMAIN')],
```

The token is 40 bytes from `random_bytes`, stored as a SHA-256 digest, single-use via an atomic
conditional `UPDATE`, and valid for 60 seconds. Redemption re-runs the **entire** authorization
stack rather than trusting the decision made when the token was minted — a role can be withdrawn
in the seconds between issuing a link and following it. See [the security model](../security.md).

Two audit rows are written for a token handoff, and the distinction is deliberate: `begin()`
records that a link was issued, and redemption records the impersonation that actually happened,
at the moment and on the host where it happened. Those are different facts.

## `tenancy`

For stancl/tenancy. Resolves the tenant, initialises its context, and impersonates inside it.

```php
Impersonator::enter($customer, driver: 'tenancy');
```

The tenant id is recorded on the audit row, so a central audit trail can answer "who accessed
this tenant" — which is the question a multi-tenant compliance review actually asks. Set
`audit.connection` to keep those records centrally while the application runs per-tenant.

This driver uses stancl for tenant resolution and **not** for the handoff. stancl's own
`UserImpersonation` stores tokens unhashed with a non-atomic single-use check and authenticates
with `loginUsingId()`, which fires login events for somebody who is not there; the token
machinery here is used instead. See [Comparison](../comparison.md).

## Writing your own

```php
use Simtabi\Laranail\Impersonator\Core\Contracts\ImpersonationDriver;

Impersonator::extend('sso', fn ($app) => new SsoDriver(/* ... */));
```

```php
'driver' => 'sso',
```

The contract is four methods — `begin`, `complete`, `end`, `current`. Register it in a service
provider's `boot()`; the manager caches resolution per name.

A driver is responsible for opening the audit row **before** authenticating. If authentication
fails halfway, the attempt must still be on record — a row written only after a successful login
records only the impersonations that worked.

---

[← Docs index](../../README.md#documentation)
