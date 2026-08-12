# Changelog

All notable changes to `laranail/impersonator` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-12

First release.

### Added

- Layered architecture: a pure-PHP `Core` domain layer depending only on PSR
  interfaces, and a `Laravel` bridge. Enforced by Pest architecture tests rather
  than convention.
- Seven Core contracts: `TokenRepository`, `AuditStore`, `TrailStore`,
  `AuthAdapter`, `ImpersonationDriver`, `AuthorizationPolicy`, `ModeEnforcer`.
- Core value objects: `Identity`, `Mode`, `Guards`, `Decision`, `Token`,
  `Credential`, `AttemptedAction`, `ImpersonationRequest`,
  `ImpersonationSession`, `ImpersonationOutcome`, `TrailEvent`, plus the
  `EndReason` and `CredentialType` enums.
- `ImpersonationManager`, composing the two orthogonal axes — drivers (where an
  impersonation happens) and auth adapters (what authenticating the target
  consists of) — with lazy, cached resolution and `extend()` / `extendAdapter()`
  / `registerMode()` extension points.
- `ImpersonatorFacade`, aliased as `Impersonator`, plus an `impersonator()` helper
  and container bindings.
- `IdentityResolver`, enforcing the impersonatable-target allowlist that blocks
  arbitrary model class injection.
- The full published config file, covering drivers, adapters, guards, modes,
  targets, authorization, limits, rate limiting, tokens, sessions, audit, trail,
  causer attribution, routes, URLs, redirects, banner, API, notifications,
  approval and logging.
- `SessionDriver` for same-application impersonation. Opens the audit row before
  authenticating, so an impersonation cannot happen without a record of it.
- `SessionGuardAdapter` for stateful guards, including Sanctum's SPA cookie mode:
  session id regenerated on enter and leave, remember-me never issued,
  `silent_login` so the application's own Login listeners do not fire, and
  support for a different guard on each side.
- `BasePolicy`, the always-on authorization stack: master switch,
  self-impersonation, nesting, soft-deleted targets, the target allowlist, the
  `canImpersonate()` / `canBeImpersonated()` model hooks, the `impersonate` gate
  ability, a bounded required reason, and the concurrency caps.
- `Impersonates` trait, delegating to the same authorization stack the facade
  uses so a model method cannot bypass it.
- `RedirectGuard`, validating every redirect the package emits: relative paths
  only by default, with exact-match host allowlisting for absolute URLs.
- Blade `@impersonating`, `@impersonationMode`, `@canImpersonate` and
  `@impersonationBanner`, plus a themeable banner (auto/light/dark, top/bottom)
  that escapes the user-supplied display name.
- The leave route and a `Route::impersonate()` macro.
- `ImpersonationStarted`, `ImpersonationEnded` and `ImpersonationRejected` as
  plain PHP events, dispatchable by Laravel and PSR-14 alike.
- Structured PSR-3 lifecycle logging, with refusals and involuntary ends logged
  at a higher level than routine activity.
- `Settings`, typed reads of the package config so a malformed value degrades to
  its documented default instead of being coerced into a surprise.
- **Failure-handling standard adopted.** `Criticality`, `FailureReport` (observable
  degraded state), `FailurePolicy` (classify → guarded report → crash-on-critical →
  record-and-continue), `OperationFailed` carrying structured context with the cause
  chain preserved, and `LaravelFailureReporter` routing to the central handler with an
  `error_log` last resort. Every boot operation is classified, critical-first, with no
  environment branching, plus a boot-health CI gate.
- **Actions → Services architecture.** `EnterImpersonation`, `LeaveImpersonation` and
  `RevokeImpersonation` as single-purpose invokables, composed by
  `ImpersonationService`. The manager is now purely the composition root.
- **Complete event surface** (14 events): adds `ImpersonationRequested`,
  `ImpersonationRevoked`, `ImpersonationExpired`, `ModeViolationBlocked`,
  `HandoffTokenIssued` / `Redeemed` / `Rejected`, `ApprovalRequested` / `Granted` /
  `Denied` and `TargetNotified`.
- **Durable audit and trail**: `impersonator_audits`, `impersonator_audit_events`,
  `impersonator_tokens` and `impersonator_approval_requests` migrations,
  `EloquentAuditStore` (cached per-request lookups, concurrency caps enforced inside a
  locked transaction) and `EloquentTrailStore` (a failed trail write is degradable, so
  observability never becomes an outage).
- **`read_only` and `limited` modes** with `EnforceImpersonationMode`. The strict
  `prevent_writes` net uses `DB::beforeExecuting`, which sees query-builder and raw
  writes that Eloquent model events miss.
- **Remote revocation and `max_duration`** via `GuardImpersonationLifetime`.
- **Action trail middleware** with recursive, case-insensitive `Redactor`, sampling and
  path ignores.
- **Blade component library**: `<x-impersonation-banner />`, `<x-impersonate-button />`,
  `<x-impersonation-leave-button />`, `<x-impersonation-badge />` and
  `<x-when-impersonating>`, each rendering nothing when inapplicable so they can be
  dropped into a layout unconditionally. Also namespaced as `x-impersonator::*`.
- **Form Requests, gates and routes**: `EnterImpersonationRequest` and
  `RevokeImpersonationRequest` validating the target against the morph allowlist, the
  mode against the registry, the guard against `config('auth.guards')` and redirects
  through the redirect guard; POST enter/revoke endpoints; gates delegating to the one
  AuthorizationPolicy; named rate limiters.
- **`LaravelClock`** (PSR-20) so every expiry decision answers against the same clock
  as the application, including a mocked one.
- Package refusals now render as 403/429 with safe messages rather than 500s.
- **`RbacPolicy`**, the role-based layer: the enter permission, per-mode permissions
  (what pins junior staff to `read_only`), protected roles that no amount of privilege
  can reach past, and a role-hierarchy rule with a configurable closure override that
  fails closed. Duck-typed against `hasPermissionTo()` / `hasRole()`, so it works with
  spatie/laravel-permission without depending on it, and auto-selects when that package
  is installed.
- **`CauserResolver`** for activity-log attribution, with `impersonator` (default),
  `target` and `both` strategies. Always carries the audit id in the properties so a log
  entry can be reconciled against the trail.
- **Notifications**, both off by default: `TargetAccountAccessed` (queued, plain-language
  mode explanation, deliberately never naming the operator) and
  `ImpersonationSecurityAlert` (full-mode entries and every revocation, naming the
  operator because a security team needs it actionable). Driven by the event surface via
  a listener, so a host can unsubscribe and substitute its own; every send is degradable.
- **`SessionTerminator`**: revocation now destroys the target's session immediately
  through the session handler, so it takes effect at once rather than on their next
  request. Works for every server-side driver (file, database, redis, memcached) via
  `SessionHandlerInterface::destroy()`, so a driver added later needs no change here;
  `array` and `cookie` keep no server-side record and fall back to the enforcement
  middleware, which the doctor command reports. Refuses to destroy the caller's own
  session. Gated by `session.destroy_on_revoke`.
- **Multiple impersonatable models**, with `ImpersonatableType` + `TargetRegistry`. Each
  `targets.allowlist` entry may be a bare class or a descriptor with its own `guard`,
  `display_name` and `label` — so a marketplace can impersonate customers on `web` and
  vendors on `vendor`, which a single global target guard cannot express. Types may also
  be registered at runtime with `Impersonator::registerTarget()`, letting a package ship
  its own type without the host editing config; runtime registrations override config of
  the same alias.
- Audit rows now store `impersonator_label` and `target_label`, so a row stays readable
  after a rename or a deletion instead of resolving today's names against yesterday's
  actions.
- Session-driver compatibility suite covering the full lifecycle on `file`, `database`,
  `cookie` and `array`.
- **`TokenDriver`** for cross-domain and cross-subdomain impersonation. `begin()` mints a
  single-use token and returns a *pending* outcome with an accept URL — nobody is
  impersonating until it is followed — and `complete()` re-runs the entire authorization
  stack, because a permission can be withdrawn between minting a link and following it.
  A refused redemption still burns the token.
- **`EloquentTokenRepository`**: 40 bytes from `random_bytes` with a 32-byte floor, stored
  and looked up as a SHA-256 digest so a database leak yields nothing redeemable, and
  redeemed by a single atomic `UPDATE … WHERE consumed_at IS NULL` — a read-then-write pair
  is a replay window that only appears under load. Every rejection is indistinguishable to
  the client; the reason reaches only the log.
- **`AcceptUrlBuilder`** with `domain`, `subdomain` and `path` strategies, scheme and
  explicit port support, mid-path token substitution, and `resolveAcceptUrlUsing()` as the
  documented override.
- Throttled `accept` route with a bounded token parameter, plus `AcceptImpersonationRequest`.
- `laranail::impersonator.prune-tokens`, with a local `SupportsNamespacedNames` trait so the
  `::` command shape works without raising the PHP floor to `laranail/console`'s ^8.4.1.
- **`SanctumTokenAdapter`**: a short-lived personal access token for the target, scoped to a
  single `impersonated` ability rather than `*`, named after the audit row so a leaked token
  traces to the operator, with a lifetime independent of the app's own Sanctum expiration.
  Written through Sanctum's token model rather than the target's `createToken()`, so the
  target needs neither the `HasApiTokens` trait nor its contract — Laravel's default `User`
  uses the trait without the interface, and requiring either would refuse the commonest
  setup there is. Revocation deletes the row, so it takes effect immediately.
- **`PassportAdapter`**: an access token with an `impersonated` scope and **never a refresh
  token**, which would let an impersonation renew itself past its own audit row. Registers
  its scope with Passport (which rejects unknown scopes), and translates Passport's opaque
  setup errors — missing keypair, missing personal access client, no `passport` guard — into
  a message naming the fix.
- **`JwtAdapter`**: mints with `imp_by`, `imp_audit` and `imp_mode` claims, so a resource
  server that has never heard of this package can still refuse a write from a `read_only`
  impersonation. Short TTL applied per mint and restored afterwards, since jwt-auth's
  factory TTL is global state. Reports `revoke()` as false rather than implying a revocation
  that will not happen; `blacklist()` is available to a caller still holding the token.
- All three adapters are registered unconditionally and report `isAvailable()` false when
  their package is absent, so a misconfiguration fails loudly at selection rather than
  mysteriously at use. All three are integration-tested against the real packages.
- **`TenancyDriver`** for stancl/tenancy installations, registered only when stancl is
  present and never required. It requires an initialized tenant to enter, and verifies on
  redemption that the token was minted for the tenant being redeemed on — reported as
  `unknown`, since naming a tenant mismatch would confirm the token is real and disclose that
  another tenant exists.

  It deliberately does **not** call `UserImpersonation::makeResponse()`. stancl's own feature
  stores its token id unhashed as a primary key, checks single use by deleting after a
  non-atomic read, and redeems through `loginUsingId()` — so no session regeneration, no
  silent login, no audit row and no mode, and it `abort(403)`s so a replay is
  indistinguishable from a typo. Several of those are outright regressions against the token
  driver already here, so this reuses that machinery instead: a hashed 40-byte token claimed
  by a single atomic UPDATE, redeemed through our own adapter. Tests assert the session *is*
  regenerated and the target's Login listeners do *not* fire.
- `auto` driver resolution verified against a real initialized tenant.
- **`AuditChain`** tamper evidence: a keyed HMAC over each row's immutable opening facts, chained
  to its predecessor, so altering, deleting or back-dating a row breaks the chain from that point.
  Keyed rather than a bare digest because a plain chain is recomputable by anyone holding the
  algorithm — which is anyone with write access to the table. Covers the opening facts only, not
  the later terminal transitions, and says so. `laranail::impersonator.verify-audit` walks the
  chain, names the first break and exits non-zero so it can be scheduled.
- **`AuditExporter`** + `laranail::impersonator.export-audit`: one impersonation and its full
  action trail as json or csv, paged so a long session does not load whole. The credential hash
  and session id are never included — an export leaves the building, and a digest is still a
  verifier for a guessed token. One implementation shared by the command and the API.
- **`laranail::impersonator.enter`** for a support engineer at a shell, printing a one-time accept
  URL with an explicit warning that it is a live credential. Requires `--as` so the audit row
  names a real operator, records `entered_via: console`, and refuses an ambiguous bare id when
  several target types are registered.
- **`ImpersonationAuditPolicy`** registered on the gate, so `$user->can('view', $audit)` and
  Blade's `@can` cover an audit UI. Delegates every decision to the one AuthorizationPolicy, and
  gates revocation separately from reading — an auditor who may read every impersonation has no
  business ending one.
- `IdentityResolver::resolveActor()` resolves the impersonator side *without* the target
  allowlist. The allowlist governs what may be impersonated; requiring operators to be
  listed would force an `Admin` model that enters as `User` into the list of accounts
  that can be impersonated, which is backwards.
- **REST API, off by default** — eleven endpoints behind `api.enabled`, because an impersonation
  API is a remote-control surface for every account in the system and nobody should acquire one by
  upgrading a package. `AuditService` for the read path (every filter applied in SQL, since an
  audit table only grows), JSON resources that return the value objects' own safe projections so a
  credential cannot be re-added by hand, and API Form Requests that *extend* the HTML ones so two
  copies of the rules cannot drift. `POST /impersonations` is the only endpoint that ever emits a
  secret. An unknown filter value is a 422 rather than an empty page, which would read as "no
  impersonations happened" — the worst possible answer to an audit query.
- `docs/openapi.yaml`, an OpenAPI 3.1 contract covering all eleven endpoints, every status code and
  the full set of stable refusal codes.
- **Break-glass approvals**: `ApprovalStore` (an eighth Core port), `ApprovalState`,
  `ApprovalRequest`, `EloquentApprovalStore`, `RequestApproval` / `DecideApproval`,
  `ApprovalService`, and the queue endpoints. An approval is a **one-time permit** — `approved` and
  `consumed` are separate states, because collapsing them would turn one sign-off into standing
  access for as long as the row survives. The permit is fingerprinted over requester + target +
  mode, so it cannot be spent on a higher mode, a different account, or by a colleague; it is
  deliberately *not* bound to the reason text, the IP or the user agent, none of which indicate
  anything suspicious. Spending it is one atomic conditional `UPDATE`. The approver can never be
  the requester, enforced against the row rather than left to the UI, and `impersonator.enter` does
  not confer `impersonator.approve` — otherwise any two support staff could clear each other's
  requests. `read_only` is exempt by default, which is the point rather than a loophole: requiring
  a second person for routine work trains everyone to approve reflexively.
- `ApprovalRequired` renders as **202**, not 403 — the caller holds every permission the request
  needed and something was created. `ApprovalNotDecidable` renders as 409.
- `authorizeApproval()` on `AuthorizationPolicy`, so approving is a fourth distinct permission
  alongside entering, revoking and reading the trail.
- `ApprovalRequestedNotification` and `ApprovalDecided`, with a configurable approver resolver
  (this package duck-types an RBAC surface rather than depending on one, so it cannot query
  "everybody holding `impersonator.approve`" itself). The requester is filtered out of the
  resolver's result, and neither mail carries an approval link or a credential — a one-click
  approve token would move the four-eyes control into an inbox.
- `laranail::impersonator.prune-approvals`, which expires rather than deletes: removing the record
  that somebody asked for access to an account is exactly what an auditor came to read.
- **`laranail::impersonator.doctor`** — fourteen checks for the things that are wrong *silently*,
  since a missing table throws on first use and needs no doctor. Boot health, the enter-plus-mode
  permission trap, whether a revocation can genuinely end a session on the configured store, an
  API exposed without an auth guard, tamper evidence enabled without a key, and other
  impersonation packages. Three severities where only real failures exit non-zero, so it works as
  a CI gate and a warning for a deliberate choice does not train teams to ignore it. It resolves
  the manager and policy defensively, so it still reports on an install broken enough that neither
  can be built — which is the case it exists for.
- The doctor's target check compares the raw allowlist against what actually resolved, because the
  registry drops a non-model entry silently; iterating the registry would never see the broken
  entry, since the broken entry is the one that is missing.
- `doctor.conflicting_packages` is config-driven, so an application can add whatever else it knows
  conflicts.
- **`php artisan about` panel** reporting the facts that change what impersonation does — driver,
  adapter, default mode, max duration, approval, tamper evidence, API. Never the audit hash key or
  a webhook URL, because `about` output is what people paste into bug reports.
- CI: PHP 8.3/8.4/8.5 × Laravel 13 with a `prefer-lowest` run on the floor; a job running the
  suite with Sanctum, Passport, JWT and stancl **removed** (and asserting they really are absent,
  so it cannot pass while testing the wrong thing); a boot-health gate; PHPStan at level max with
  no baseline; Pint; Rector; the layering test as its own job; and `composer validate`.
- Documentation: 30 pages across guides, per-subsystem reference and task recipes, including a
  security model page and an honest comparison against lab404, octopyid, stechstudio and stancl's
  built-in impersonation.

### Fixed

- `LeaveImpersonation` re-reads the audit row after closing it, so a caller learns *how* it ended.
  It previously returned the snapshot taken before the close, which meant an API response reported
  a null `ended_by` for a completed leave — a response contradicting itself.
- The audit listing endpoint 404s for an id that matches nothing, rather than surfacing
  `AuditRowMissing`. That exception means state was lost between opening a row and acting on it,
  which is a bug signal; an id typed by a client is an ordinary not-found.

[0.1.0]: https://github.com/laranail/impersonator/releases/tag/v0.1.0
[Unreleased]: https://github.com/laranail/impersonator/compare/v0.1.0...HEAD
