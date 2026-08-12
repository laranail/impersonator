# Break-glass approvals

Four-eyes authorisation: an impersonation that needs a second operator's sign-off before it starts.

```php
'approval' => [
    'require'      => true,
    'ttl'          => 15,
    'except_modes' => [Mode::READ_ONLY],
],
```

Off by default.

## The flow

```php
try {
    Impersonator::enter($customer);
} catch (ApprovalRequired $e) {
    $e->approvalId;   // a request is now waiting
    $e->expiresAt;
}
```

Nobody is impersonating anything at this point. A second operator decides:

```php
use Simtabi\Laranail\Impersonator\Laravel\Services\ApprovalService;

app(ApprovalService::class)->grant($approvalId, $approver, note: 'Incident #77');
```

Then the **requester** retries their original call, which now succeeds. Granting does not start the
impersonation, deliberately: if it did, the audit trail would name the person who permitted the
work rather than the one who did it.

## More than one reviewer

```php
'approval' => [
    'policies' => [
        'default' => ['quorum' => 1, 'roles' => []],
        'full'    => ['quorum' => 2, 'roles' => ['manager' => 1, 'auditor' => 1]],
    ],
],
```

Per mode, falling back to `default`. A `full`-access request warranting two reviewers while read-only
work needs one is the ordinary shape of this control.

Four semantics, each chosen rather than fallen into:

| Rule | Why the alternative is worse |
|---|---|
| **One denial is terminal** | A reviewer who spots a problem should not have to persuade the others, and failing closed is the only safe reading of a disagreement |
| **One reviewer fills one role slot** | Otherwise somebody holding `manager` and `auditor` satisfies a two-role policy alone, and the separation of duties is theatre |
| **Requirement is `max(quorum, sum(roles))`** | `quorum` stays an independent floor: three reviewers of whom one is an auditor needs three, not one |
| **`quorum` is floored at 1** | A zero would mean "approval required" and "nothing required" at once |

Roles are matched against the model's own `hasRole()` / `getRoleNames()` — the same duck-typed surface
the RBAC policy uses, so there is no hard dependency and any permission package works. A model
exposing neither has no roles, which makes a role-based policy unsatisfiable: visibly, rather than by
accident.

### `partially_approved`

A new state, and the distinction matters to a queue: `pending` means nobody has looked, and
`partially_approved` means somebody has and it is short of quorum. Both are **open**, and `consume()`
refuses both — a chain short of quorum is not a permit.

That state being *open* is load-bearing. If it read as closed, the sweeper would expire a chain out
from under reviewers still working through it.

### Each reviewer gets their own row

Decisions live in `impersonator_approval_decisions`, one per reviewer, with a **unique index on
(approval, reviewer)**. Two reasons, both structural:

- Three columns on the request row could hold exactly one answer, so a second reviewer would have
  overwritten the first — losing the only fact an audit of a four-eyes control is about.
- A guard in PHP cannot stop one reviewer counting twice. Two requests from the same approver both
  read no prior decision and both write, so a two-reviewer policy ends up satisfied by one person. The
  index makes that impossible rather than unlikely, and the store treats its violation as the answer.

The quorum recount runs inside a transaction holding a write lock on the request row, so two reviewers
granting at once cannot both observe "one of two".

### An extra rule of your own

```php
Impersonator::approvalEligibilityUsing(
    fn (Model $reviewer, ApprovalRequest $request): bool => $reviewer->manages($request->requester),
);
```

For what config cannot express — *"must be the requester's line manager"*, a relationship this package
has no business modelling. Layered **on top of** the approve permission and the role slots, never
instead of them.

**Fails closed.** Anything other than a literal `true` refuses, including a truthy string and a thrown
exception: the point of registering a rule is that the package cannot judge the relationship, so a
rule that errors is not consent. A refusal reports `approver_not_eligible`.

### Reading the chain

```php
$service->decisions($id);   // list<ApprovalDecision>, oldest first
$service->progress($id);    // required, approved, outstanding, outstanding_roles
```

Over the API both arrive in `meta` rather than `data`: `data` is the request's own shape and a client
may reasonably persist it, while the chain is progress that changes underneath them.

The fingerprint never appears in either. It is the value a permit is matched on, and an approval queue
is a screen operators holding `approve` but not `enter` can see.

## An approval is a one-time permit

This is the property everything else follows from. `approved` and `consumed` are separate states,
because "a second operator said yes" and "that yes has been spent" are different facts — collapsing
them would make one approval into standing access to that account for as long as the row survives.

Spending it is a single atomic `UPDATE ... WHERE state = 'approved'`; the affected-row count
arbitrates, so two concurrent requests cannot both spend one permit.

## The permit is bound to what was approved

A fingerprint over **requester + target + mode**. Change any of the three and the permit does not
apply:

- An approval for `read_only` cannot be spent on `full`.
- An approval for one customer cannot be spent on another.
- An approval granted to one operator cannot be spent by a colleague.

What it deliberately does **not** bind to is equally considered. Not the reason text, because an
operator fixing a typo in their justification should not need a second approval. Not the IP or user
agent, because somebody who requested from a laptop and returned on a phone has done nothing
suspicious, and binding to those would produce refusals whose cause is invisible.

## The approver is never the requester

Enforced against the row, not left to the UI. A flow where one pair of eyes can be both pairs is a
delay, not a control.

Deciding also requires `impersonator.approve`, and holding `impersonator.enter` does **not** confer
it — otherwise any two support staff could clear each other's requests.

## Authorization runs first

The approval gate sits *after* the full authorization stack. An operator who may not impersonate
that account at all is refused outright rather than having their request put in front of an
approver — which would convert a refusal into a queue entry that teaches them the account exists,
and invites an approver to grant something the policy will refuse a second time anyway.

## Exempt modes are the point, not a loophole

`read_only` is exempt by default. Requiring a second person for routine read-only support work
trains everyone to approve reflexively, which is how a four-eyes control degrades into a rubber
stamp. Exempt the modes where the friction buys nothing and keep it where the access is real.

## The queue

```php
$approvals = app(ApprovalService::class);

$approvals->queue();                              // awaiting decision (needs `approve`)
$approvals->mine($operator);                      // the caller's own, any state
$approvals->find($approvalId);
$approvals->hasPermit($customer, 'full', $op);    // "approved — you may now enter"
$approvals->deny($approvalId, $approver, 'Not warranted');
```

Expired requests are omitted from the queue: a queue listing dead requests invites somebody to
approve one and wonder why nothing happened.

Never gate an entry on `hasPermit()` — checking there and entering afterwards is exactly the race
that the atomic spend inside `EnterImpersonation` exists to close.

## Expiry

Enforced when a permit is read, so a stale request is dead at its TTL whether or not anything swept
it. The sweep exists for the notification:

```bash
php artisan laranail::impersonator.prune-approvals
```

Worth scheduling. It marks timed-out requests expired and fires `ApprovalDenied(expired: true)`,
which is how a waiting operator learns that nobody replied — the difference between them escalating
and them assuming the system is broken.

Expiring is not deleting. Open requests are never pruned however old they look: removing the record
that somebody asked for access to an account is exactly what an auditor came to read.

## Notifications

```php
'notifications' => [
    'approvals' => [
        'enabled'          => true,
        'mail'             => ['security@example.com'],
        'resolver'         => fn ($request) => User::role('approver')->get(),
        'notify_requester' => true,
    ],
],
```

The package cannot find your approvers itself — it is duck-typed against an RBAC surface rather
than depending on one, so it has no way to query "everybody holding `impersonator.approve`". Supply
a resolver, or list plain addresses.

The requester is filtered out of the resolver's result even if returned, and the notification
carries **no approval link and no credential**: a mail with a one-click approve token would move
the four-eyes control into an inbox.

## Over the API

| Endpoint | Does |
|---|---|
| `POST /impersonations` | Returns **202** with the approval id when one is required |
| `GET /approvals` | The queue (needs `approve`) |
| `GET /approvals/mine` | The caller's own requests (no permission) |
| `POST /approvals/{id}/grant` | Approve |
| `POST /approvals/{id}/deny` | Refuse |

202 rather than 403: the caller holds every permission the request needed and nothing was refused.
Rendering it as a denial would send an operator asking for permissions they already have.

A 409 means the request cannot be decided as asked — already answered, expired, or the approver's
own. See [The REST API](rest-api.md).

## Events

`ApprovalRequested` · `ApprovalGranted` · `ApprovalDenied` (also fired with `expired: true`).

---

[← Docs index](../../README.md#documentation)
