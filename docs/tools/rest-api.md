# The REST API

Eleven endpoints for starting, inspecting and ending impersonations, reading the trail, and
deciding break-glass requests.

**Off by default.**

```php
'api' => [
    'enabled'      => env('IMPERSONATOR_API_ENABLED', false),
    'prefix'       => 'impersonator/api/v1',
    'middleware'   => ['api', 'auth:sanctum'],
    'per_page'     => 25,
    'max_per_page' => 100,
],
```

An impersonation API is a remote-control surface for every account in the system. Nobody should
acquire one by upgrading a package, which is why this is opt-in rather than opt-out.

The full contract is in [`docs/openapi.yaml`](../openapi.yaml) — an OpenAPI 3.1 document you can
load into any client generator.

## Endpoints

| Method | Path | Needs |
|---|---|---|
| `POST` | `/impersonations` | `enter` + the mode permission |
| `GET` | `/impersonations/current` | — |
| `DELETE` | `/impersonations/current` | — |
| `POST` | `/impersonations/{audit}/revoke` | `revoke` |
| `GET` | `/audits` | `audit.view` |
| `GET` | `/audits/{audit}` | `audit.view` |
| `GET` | `/audits/{audit}/export` | `audit.view` |
| `GET` | `/approvals` | `approve` |
| `GET` | `/approvals/mine` | — |
| `POST` | `/approvals/{approval}/grant` | `approve` |
| `POST` | `/approvals/{approval}/deny` | `approve` |

Permissions are checked by the same `AuthorizationPolicy` the HTML endpoints use, inside the
actions — so the API and the web surface cannot drift. The API Form Requests literally extend the
HTML ones for the same reason.

## Starting one

```http
POST /impersonator/api/v1/impersonations

{ "target_type": "user", "target_id": "9902", "mode": "read_only", "reason": "Ticket #4182" }
```

**201** with a live impersonation, or a pending handoff for the token driver:

```json
{
  "data": {
    "pending": true,
    "impersonation": { "id": "01k...", "mode": "read_only", "active": true },
    "accept_url": "https://app.example.com/impersonator/accept/...",
    "credential": null
  }
}
```

`pending: true` means **nobody is impersonating yet** — the operator must follow `accept_url`.

This is the **only** endpoint that ever returns a secret. Treat the whole response as one: do not
log it and do not persist it. Both the accept URL and a credential secret are single-use,
short-lived, and unrecoverable afterwards.

**202** means a break-glass approval is required — see [Approvals](approvals.md).

## Reading the trail

```http
GET /audits?target=user:9902&mode=full&active=1&per_page=50
```

Filters: `impersonator`, `target` (`type:id` or a bare id), `tenant`, `mode`, `driver`, `ended_by`,
`active`, `from`, `to`, `per_page`.

An unknown filter value is a **422**, not an empty page. A silently empty result reads as "no
impersonations happened", which is the worst possible answer to an audit query. `per_page` above the
cap is likewise a 422 rather than a silent downgrade, so a client paging a long trail cannot
conclude it read everything from a page smaller than the one it asked for.

## What no response ever contains

No credential hash and no session id — not in a listing, a detail view, or an export. A digest is
still a verifier: a holder can confirm a guessed token against it.

This is structural. `ImpersonationResource` and `TrailEventResource` are one line each — they return
the value object's own safe projection rather than assembling fields, so a credential cannot be
re-added by hand.

## Status codes

| Code | Means |
|---|---|
| 200 | Done |
| 201 | An impersonation was created |
| 202 | Approval required; a request is waiting |
| 204 | Nothing to report (not impersonating; nothing to leave) |
| 403 | Refused — `reason` carries a stable code |
| 404 | No such target or audit row |
| 409 | An approval cannot be decided as asked |
| 422 | Validation failed |
| 429 | Rate limited |

204 rather than 404 for "not impersonating": the resource is the caller's own state, which exists
and is simply empty. A 404 would suggest the endpoint was wrong.

## Refusals

```json
{ "message": "You cannot impersonate yourself.", "reason": "self_impersonation" }
```

Branch on `reason`, never on `message` — the message is translatable and will change. The full set
is in [Authorization](authorization.md).

## Rate limiting

```php
'rate_limiting' => ['api' => ['attempts' => 30, 'per_minutes' => 1]],
```

Applied to `POST /impersonations`, the revoke endpoint, and both approval decisions. Keyed per
operator rather than per address: the risk is one authorised person enumerating accounts, and they
do it from a single address.

## Leaving needs no permission

`DELETE /impersonations/current` is deliberately unauthorised beyond being a known caller. Leaving
only de-escalates, and an operator whose access was revoked mid-session must still be able to stop.

---

[← Docs index](../../README.md#documentation)
