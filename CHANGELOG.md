# Changelog

All notable changes to `laranail/impersonator` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Timed impersonation with in-session extension.** Every impersonation already carried a deadline;
  it is now short by default and extendable in place rather than only configurable upward.
  `limits.max_duration` defaults to **10 minutes** (was 60), and `limits.extension` lets an operator
  buy another window from inside the session — via the banner's Extend button,
  `Impersonator::extendSession()`, `POST impersonator/extend`, or
  `POST impersonator/api/v1/impersonations/current/extend`.

  The short default is the control and the extension is what keeps it usable: without an escape valve
  the pressure is to raise the window "just in case", and a long window is what a short one exists to
  avoid. Five properties make it safe to offer:

  - **Bounded twice** — a count (`extension.max`, default 3) *and* a total elapsed ceiling
    (`extension.max_total_duration`, default 60 minutes), stricter wins. Neither suffices alone: a
    count bounds no amount of time when the window length is configurable, and a total alone never
    asks the operator to re-justify. Both null makes the deadline advisory, and the doctor warns
    about exactly that combination.
  - **Atomic** — the caps are evaluated against the row *inside* a locked transaction, so two clicks
    on the button spend one allowance rather than two.
  - **Monotonic** — the expiry may only move forward. `extend` is the only non-terminal mutation the
    audit store exposes, and it cannot shorten a live impersonation or rewrite its opening facts.
  - **Cannot outrun a revocation** — extending is refused in the window where a row is marked revoked
    but its session has not yet made the request that closes it.
  - **Permission is re-checked**, not inherited from the session existing. Extending asks for *more*
    access, unlike leaving, which only de-escalates.

  The audit hash chain is unaffected: `expires_at`, `extensions` and `extended_at` are not among the
  chained facts, so moving the deadline can neither forge tamper evidence nor break it. New columns
  `extensions` and `extended_at` record the count and the last time, because a row reading "fifty
  minutes" cannot answer whether anyone decided to stay. New event `ImpersonationExtended`, new
  decision codes (`extension_disabled`, `extension_limit`, `extension_ceiling`, `extension_too_early`,
  `not_impersonating`), and a doctor check reporting the effective ceiling.

  The last extension before the ceiling is **clamped rather than refused**, so the whole allowance
  stays usable — asking for ten more minutes when four remain grants four.

- **Four operator-side controls, all off by default.** `authorization.step_up` requires a recent password
  confirmation before entering — the strongest control here, what GitLab's Admin Mode exists to provide,
  and what ASVS 7.5.3 asks for. It refuses on an **absent** timestamp as well as a stale one, since an
  install that forgot the host-side `password.confirm` flow produces exactly the absent case.

  `limits.max_idle` ends an impersonation left sitting, which `max_duration` cannot: an absolute cap
  alone leaves an abandoned tab open for the whole window. Tracked in the session, so it costs no query,
  and an absent stamp reads as "first request" rather than infinitely old — otherwise every impersonation
  would die on its second request.

  `authorization.recheck_each_request` re-checks the operator's permission on every impersonated request,
  memoised per request. Without it, revoking a role leaves live sessions running until the duration cap —
  the withdrawal that mattered most taking effect last.

  `targets.eligibility` is a per-instance hook for what this package cannot know: blocked,
  password-expired, internal and bot accounts. Fails closed on anything but a literal `true`.

  Each defaults off because each can refuse an impersonation an installation expects to work, and that
  default is itself asserted — a control switching itself on during an upgrade would break support
  workflows at the worst moment.

- **Safe on Octane and other long-running servers.** All seventeen singletons were audited for mutable
  state rather than assumed about. Exactly two hold request state and are now reset on both
  `RequestReceived` *and* `RequestTerminated` — both, because a request that dies hard never reaches the
  second: `PersistenceGuard` (armed for one request with one impersonation) and `FailureReport` (which
  otherwise made `isHealthy()` false for the life of the worker after one transient blip; `flush()`
  existed for this and nothing called it).

  Everything else holds either nothing or **boot-time registrations that must survive** — the manager's
  driver factories, the eligibility closure, the mode enforcers. Resetting those would delete a custom
  driver an application registered, which is worse than the bug being fixed. `TargetRegistry`'s config
  memo is deliberately kept warm. This is a named failure mode in exactly this domain:
  `stechstudio/filament-impersonate` #146 is *"impersonation targets the wrong user under
  Octane/Swoole"*, and wrong-user is data exposure. A doctor check fails when Octane is present and the
  resets are not registered.

- **PostgreSQL row-level security.** `RlsContext::effective()` returns the impersonated account, which is
  the whole fix for the inversion that makes RLS dangerous here: an application scoping on `auth()->id()`
  shows an impersonated session the *operator's* rows while claiming to be the customer.

  Optional `impersonator.rls` middleware publishes the context as GUCs so a policy can also refuse writes
  under `read_only` at the database level — defence in depth, not a replacement, because a write blocked
  only by a policy cannot be reported as a `ModeViolationBlocked` event.

  Two implementation rules, both asserted rather than trusted: **`select set_config(?, ?, true)` with
  bindings, never `SET LOCAL app.x = '…'`** (`SET` cannot take a bind parameter, so that shape has to
  concatenate identity into SQL), and **transaction scope, never session scope** (a session GUC leaks to
  the next client PgBouncer hands the connection to — a data breach, and the most-cited RLS footgun).

  Plus a doctor check reading `pg_class.relrowsecurity` for the five package tables: a policy hiding an
  audit row makes `verify-audit` report a chain break that never happened, because each digest covers its
  predecessor's.

- **`laranail::impersonator.scrub-identity` for GDPR erasure.** The audit labels are denormalised PII on
  purpose, so a row stays readable after a rename — which means an erasure request otherwise leaves a
  customer's name in the trail with only retention to clear it. This nulls the labels for one identity and
  keeps the row, its ids and **the hash chain**, which covers the immutable opening facts and not the
  labels. Verified: `verify-audit` still passes after a scrub. It does not delete rows — erasing the
  record that an account was accessed would remove the controller's own evidence of processing.

- **PostgreSQL and MySQL now run in CI**, whole suite, with the `locking` group **asserted to actually
  run** rather than skip — without that the job could silently degrade to the SQLite behaviour it exists
  to escape. Both were verified locally first, MySQL in a container, with nothing skipped on either — the
  whole suite, not a subset, because the interesting failures were the ones no driver-specific test
  predicted. A coverage job reports without gating, since a percentage threshold invites raising the number
  with tests that execute lines and assert nothing.

  `docs/installation.md` now states the matrix honestly, including that **SQL Server is parsed but
  untested** — the mode guard handles `[dbo].[table]`, but `lockForUpdate()` compiles to table hints with
  different semantics there and no job exercises it.

- **`limited` mode now enforces under Livewire instead of documenting that it cannot.** Every Livewire
  action POSTs to one endpoint with the component and method in the payload, so `deny_routes`,
  `deny_paths` and `allowed_methods` see one route, one path and one method for every action — a rule
  naming `password.update` matched nothing and a rule broad enough to match blocked everything. `limited`
  was therefore substantially weaker under Livewire than it read.

  New `modes.limited.deny_livewire` reads the payload and matches `Component::method` with the same
  `Str::is` patterns as `deny_routes`, at whichever granularity fits — `ProfileForm::updatePassword`,
  `BillingPanel::*`, `*::destroy`. Batched requests are checked call by call, so a denied action cannot
  ride along behind an allowed one. Both Livewire 2 and 3 payload shapes are read, because handling only
  the newer would silently enforce nothing on the older.

  Livewire stays a non-dependency: nothing type-hints a Livewire class, and the payload is read as plain
  data. Empty by default like `deny_models` — the component names are the application's — and the body is
  not parsed at all until something is configured, so applications not using Livewire pay nothing.

  An unparseable payload makes the axis **not match** rather than allow by fiat. The tests drive the
  documented payload shapes rather than a live Livewire, which proves the parsing and matching but not
  that a given Livewire release still sends that shape — stated as such in the docs.

- **The doctor did not check the approval-decisions table.** It listed four tables, the multi-reviewer
  chain work added a fifth, and nothing noticed — so a missing `impersonator_approval_decisions` was
  reported by no check at all. Its absence is the nastiest of the five to diagnose: entering works,
  requesting approval works, and the first *decision* fails, on the path a support engineer reaches only
  during an incident. Now checked, and `installation.md` lists all five.

- **Documented counts are pinned by tests rather than by care.** The doctor gained two checks and the
  docs still said nineteen; the schema gained a table and the install docs still listed four. A count in
  prose is a claim, and an unchecked claim rots — so the doctor-check count, command count, event count,
  language-file count, every middleware alias, every publish tag, and the table list are all asserted
  against the code. Where the docs also *tabulate* what they count — the five tables, the eight language
  files — every row is checked by name too, since a new entry drifts the count and the table together.

  The table assertion is behavioural: it points each table's config key at a name that does not exist and
  requires the doctor to report it. An earlier version matched the pass message for the word "five", and
  passed while the check was looking at four — the drift it existed to catch did not touch the message. A
  version after that dropped the real tables instead, which worked on SQLite and failed on PostgreSQL,
  where a foreign key refuses the drop; asserting on config needs no schema changes and is the same proof.

- **The table list has one home.** `Laravel\Support\PackageTables` holds the config-key-to-default map that
  the existence check and the row-level-security check both read. Two hand-maintained copies of that list
  is *how* the fifth table went unnoticed, so the fix is one list rather than a test per copy. The published
  migration deliberately still repeats the `config()` calls: it runs inside the host application, where it
  has to keep working after this package is removed, and a published migration that imports a class from an
  absent package cannot roll back. The test asserts the two agree by reading the schema the migration built.

- **Two commands shipped with no translated output at all.** `laranail::impersonator.export-audit` and
  `…​.scrub-identity` were both added after the localisation pass and were never revisited, so every line
  they print was hardcoded English against a documented claim that console output is translated. Both now
  have `console.php` sections. A command containing no `__()` or `trans_choice()` is now a test failure,
  because that is the shape the review missed: not a wrong string, an absent one.

- **The last twelve hand-rolled plurals are gone**, including four the localisation pass had left in place
  and one *inside the comment asserting there were none* — `console.php` said "every count below is a
  `trans_choice` line rather than a `row(s)` splice" two lines above its own `warning(s)`.

  The doctor's summary needed restructuring rather than a key: it counts failures *and* warnings in one
  sentence, and `trans_choice` pluralises on a single number, which is why the `(s)` was there. The
  warnings clause is now composed by its own `trans_choice` and spliced in already inflected, so a
  translator can also inflect it to agree with the clause around it.

  The doctor's diagnostic *detail* stays English by the standing decision — those paragraphs name config
  keys and artisan commands inline, and a half-translated sentence wrapped around `impersonator.limits.
  max_duration` reads worse than the English it replaced. So `Str::plural()` fixes them rather than a
  translation key: `1 minute(s)` was ungrammatical in the one language they are written in.

  Two remaining `(s)` were `Decision` fallbacks that never render — `decisions.php` already carries the
  pluralised form and `MessageCatalog::forDecision()` resolves it — but the literal was duplicated in two
  files and read as though it were what shipped. Reworded to need no agreement.

  Enforced by a test that scans PHP *string tokens*, not lines: prose about the pattern has to stay legal,
  and a comment-prefix skiplist got that wrong twice — it missed a `|`-prefixed line inside a block comment,
  and it needed a hand-maintained per-file exception. The tokeniser knows what a comment is.

- **A dead `composer audit` script is gone.** It was defined as `@composer audit`, which collides with
  Composer's own built-in command of that name — so Composer skipped it and printed
  `A script named audit would override a Composer command and has been skipped` on *every* invocation in
  the repository, including `composer install`. The built-in does the same job; nothing referenced the
  script. Removing it takes a permanent warning out of every contributor's terminal.

- **The sixth comparison column is filled, from the source.** The package was listed as
  `victoryoalli/laravel-impersonate`, which **does not exist** — the one under that vendor is
  `victoryoalli/laravel-multitenancy-impersonate`, and its scope is narrower than the name implied:
  landlord→tenant handoff with a hard dependency on `spatie/laravel-multitenancy`. Every cell was read
  from v2.4.0 rather than inferred, and it credits what the package does — cross-domain handoff, a
  multi-tenant driver, and a partial session record (its token table keeps impersonator, target, time and
  IP after use).

- **All fifteen events are logged, not three.** `LogImpersonationLifecycle` handled
  `ImpersonationStarted`, `Ended` and `Rejected`; the other twelve were dispatched and written nowhere.
  OWASP's Logging Cheat Sheet asks for *all actions by* privileged users and explicitly for *use of a
  break-glass account* — the previous surface missed both.

  **`ModeViolationBlocked` is the one that mattered most.** A `read_only` session attempting a write is
  either an application bug or an operator working around the boundary, and it was visible nowhere
  outside the request that produced it. It now logs at the refusal level with what was attempted, so a
  reviewer can tell a probe from a bug.

  **Every session-bearing line carries `audit_id`** as a correlation id, so one value greps a whole
  impersonation — its start, each mode violation inside it, its extensions, its end.
  `HandoffTokenRejected` is the sole exception and by construction: a rejected token has no audit row,
  so it is keyed on the IP and reason it carries.

  **Each reviewer's approval logs its own line**, not just the final transition — a chain whose
  intermediate approvals are invisible cannot answer "who signed off". `ImpersonationRequested` logs at
  `debug`, since it fires before authorization and is the highest-volume line here.

- **New `logging.audit_channel`: a separable sink for the tamper-relevant subset.** Started, ended,
  extended, revoked, expired, mode violations and every approval decision are written there **as well
  as** to the ordinary channel, never instead of it — an operator reading application logs during an
  incident should not have to know the interesting lines went elsewhere.

  ASVS 16.4.2/16.4.3 require logs that cannot be modified and are shipped off-box, and an audit table
  writable by the application's own database user meets neither. The HMAC chain gives tamper *evidence*,
  not tamper *resistance*; only an external sink closes that gap, and `docs/security.md` now says so
  plainly rather than leaving the chain to imply more than it does. A channel name that does not resolve
  is ignored rather than fatal — the ordinary line is already written, so a typo costs a copy and not a
  record.

- **Rule 9 of the failure-handling standard is implemented rather than merely documented.** A degradable
  operation that failed on every invocation reported on every invocation. That is not only noisy: it
  buries the *other* failures, and on a reporter wired to notifications it turns one broken capability
  into a page storm.

  Reports are now throttled per operation using the failure report's own first-failure-wins state, so no
  clock, cache or new dependency was needed — "have we recorded this operation" is exactly "have we
  reported it". `flush()` clears both together, so a fresh request or worker cycle reports again, which
  matters under Octane. Critical failures are never throttled: nothing continues past one, so there is
  nothing to suppress and suppressing it would be the worst possible trade.

- **Break-glass approval supports multi-reviewer chains.** `approval.policies` sets a quorum and role
  slots per mode, falling back to `default` — so a `full`-access request can need a manager *and* an
  auditor while read-only work needs one sign-off. The single-reviewer flow is unchanged and remains
  the default.

  Four semantics, each chosen against a plausible alternative and each pinned by a test naming what
  the alternative would have cost:

  - **One denial is terminal**, however many approvals precede it. A reviewer who spots a problem does
    not have to persuade the others, and failing closed is the only safe reading of a disagreement
    about access to somebody's account.
  - **One reviewer fills at most one role slot.** Otherwise somebody holding both `manager` and
    `auditor` satisfies a two-role policy alone and the separation of duties is theatre.
  - **The requirement is `max(quorum, sum(roles))`**, so `quorum` stays an independent floor rather
    than something a role map silently overrides.
  - **`quorum` is floored at 1.** A zero with no roles would mean "approval required" and "nothing
    required" at once, and the request would be born satisfied.

  **New state `partially_approved`**, and it is deliberately **open**: `pending` means nobody has
  looked, `partially_approved` means somebody has and the chain is short. `consume()` refuses both — a
  chain short of quorum is not a permit. Had it read as closed, the sweeper would have expired chains
  out from under reviewers still working through them.

  **Each reviewer now gets their own row** in `impersonator_approval_decisions`, replacing
  `decided_by_*` / `decision_note` on the request. Three columns could hold exactly one answer, so a
  second reviewer would have overwritten the first — losing the only fact an audit of a four-eyes
  control is about. A **unique index on (approval, reviewer)** is what stops one reviewer counting
  twice: a guard in PHP cannot, because two requests from the same approver both read no prior decision
  and both write. The store treats the violation as the answer rather than as an error, and removing
  the index fails three tests.

  The quorum recount runs inside a transaction holding a write lock on the request row, so two
  reviewers granting at once cannot both observe "one of two". Verified in the `locking` group, which
  skips loudly on SQLite.

  `decided_by` and `decision_note` survive as a **derived rollup** naming whoever closed the chain —
  the denier, or the last approver — rather than being dropped, so the published API shape holds. Null
  while a request is still waiting, where naming one reviewer would read as "decided by them".

  Also new: `Impersonator::approvalEligibilityUsing()` for a per-request rule config cannot express
  ("must be the requester's line manager"), layered on top of the permission and the role slots and
  failing closed on anything but a literal `true`; a `ReviewerDirectory` extracting the duck-typed
  `hasRole()` surface `RbacPolicy` already used, including the `try`/`catch` that keeps spatie's
  throwing `hasRole()` from turning a config typo into a 500 on an approval screen; and a new
  `approver_not_eligible` decision code, because "you fill no outstanding slot" is neither
  `already_decided` nor `missing_permission` — sending somebody to ask for a permission they already
  hold is how a control gets configured away.

  Chain progress and the decision list arrive in `meta` on the approval endpoints, never in `data`, and
  neither carries the fingerprint.

- **Refusal and exception messages are localisable, translated at the render seam.** New
  `resources/lang/en/` (`decisions`, `exceptions`, `modes`, `banner`), loaded under the
  `impersonator::` namespace and publishable with `--tag=impersonator-lang`. English is the only
  locale shipped.

  Translation happens in a new `MessageCatalog` in the bridge, **not in Core**. Core keeps building a
  stable code plus an English literal; the catalog swaps the literal for a line when one exists. So
  `src/Core` gains no translator contract, and the split the API already documents holds: `reason` is
  the stable code you branch on, `message` is display text that moves with the locale.

  **A decision code is not a unique message identifier** — a premise worth stating because assuming
  otherwise silently degrades output. Three different sentences share `session_terminated` (already
  ended / ended by an administrator / expired) and four share `hierarchy_violation`. Keying on the code
  alone would have collapsed them, so an operator whose session an administrator killed would read that
  it had merely expired. The lookup therefore cascades: `{code}.{detail}` → `{code}` → `{code}.default`
  → the English literal, with `detail` supplied as a context entry by the refusing call site. Fourteen
  sites gained one.

  Three properties held deliberately:

  - **A missing key degrades to English.** `has()` guards every `get()`, because Laravel's translator
    returns the *key* when it finds nothing — an unguarded lookup renders
    `impersonator::decisions.target_busy` in a user's browser, which is worse than the English it
    replaced. This is also what makes the feature adoptable one key at a time.
  - **`TokenRejected` keeps ONE line for all four factories.** Four keys would rebuild the oracle Core's
    single `PUBLIC_MESSAGE` exists to prevent: telling somebody probing the accept route that a token
    merely *expired* tells them the token was real. `ApprovalNotDecidable` is the opposite case and does
    get four — an authenticated approver looking at a request they were shown learns nothing from
    "somebody answered first".
  - **Non-scalar context is dropped, not stringified.** A context value is often a class name or an
    array of roles, and `Blocked by Array.` mid-sentence is worse than an unreplaced placeholder.

  Plurals go through `choice()` rather than a hand-rolled `impersonation(s)`, counted on an explicit
  `count` context entry — guessing from whichever numeric value happened to be present would pick `max`
  as readily as `active`.

- **Notifications, console output, validation messages and component labels are localised**, completing
  the surface. Four new files — `notifications`, `console`, `validation`, `components` — bringing the
  shipped set to eight. Four defects fell out of doing it, none of which a lang file alone could have
  fixed:

  - **The English word "at" was escaped into a date format.** `TargetAccountAccessed` formatted with
    `'j F Y \a\t H:i T'`, so a French locale rendered a French month beside an English preposition.
    Now `translatedFormat()` — and passed an explicit locale, because Carbon keeps its own and does
    *not* follow `app()->setLocale()`, which would have left an English month inside an otherwise
    translated mail. Reading the application locale also makes it honour a per-recipient
    `HasLocalePreference` for free, since Laravel wraps such a notification in `withLocale()`.
  - **`ApprovalDecided` spliced an adjective into its subject** — `'Impersonation request %s'` with
    `approved`/`denied`/`expired`. Word order is not universal, so that template cannot be translated
    correctly into a language that puts the outcome first. Three whole subjects now.
  - **Four more hand-rolled plurals** (`row%s`, `token%s`, `request%s`, `check(s)`) are `trans_choice`
    lines. Appending an `s` is only right in a language that pluralises like English, and wrong even
    in English for an irregular noun.
  - **Two component labels could not be translated at all.** `ImpersonateButton::$label` and
    `LeaveImpersonationButton::$label` were promoted-property defaults, and a promoted default must be
    a constant expression — `= __('…')` is a parse error, not a style choice. Both are nullable and
    resolve at render time; an explicit `label="…"` still wins.

  The label fix needed one non-obvious step: the resolved value is assigned **onto the property**, not
  just passed in the view data. Blade exposes a component's public properties to its template and that
  exposure *shadows* same-named render data, so a null property rendered an empty label while the data
  array held the right one.

  Staff notifications share one `fields` group for their label-value lines, so "Operator" cannot read
  differently in the security alert than in the approval request.

  **The doctor's diagnostic paragraphs stay English, deliberately.** They name config keys and artisan
  commands inline (`impersonator.limits.max_duration`,
  `php artisan vendor:publish --tag=impersonator-migrations`), and a half-translated paragraph wrapped
  around untranslatable identifiers reads worse than the English it replaced. Its short labels and
  counted summaries are translated, since those are the lines whose *shape* is language-dependent.

  Two new completeness tests, both of which found real problems while being written. One sweeps every
  translation call in `src/` and resolves its key — scoped to `__`/`trans`/`trans_choice`/`Lang::has`
  rather than every `impersonator::` literal, because Laravel shares the `namespace::` syntax between
  lang keys and **view** names, and a looser sweep reported `impersonator::components.badge` (a Blade
  view) as a missing line. The other enumerates the keys built by concatenating a runtime value onto a
  prefix, which no static check can reach.

- **The banner and badge render a mode *label*, not its config key.** Both templates ran
  `str_replace('_', ' ', $mode)` inline, which produces `read only` — a value with an underscore taken
  out, untranslatable by construction, and derived separately in two places that could drift. Both now
  read one `modeName()` on the presenter, backed by `modes.php`, and an unregistered mode still
  degrades to the humanised form (capitalised) rather than rendering blank. The raw value stays
  available as `data-impersonator-mode` for styling. **Visible change:** the badge reads `Read only`
  where it read `read only`.

- **`EndReason`, `ApprovalState` and `CredentialType` labels are translatable**, via
  `laranail/enumerator`'s `#[Label]` attribute and `IsTranslatable` trait in place of hand-written
  `match` blocks. An application can now localise them under `impersonator::enums.{slug}.{case}`
  without this package shipping a locale. `CredentialType` gains labels it never had.

  Every label is byte-identical to what the `match` returned, asserted case by case — this is a
  refactor, and a label that shifted would surface as UI nobody asked for.

  **The `value` is still the contract and is never translated.** Values are persisted in `ended_by`
  and `state`, returned by the API and matched in logs; anything branching on one branches on the case
  or the value, and a test pins that a registered translation moves the label while leaving the value
  alone.

  Two enums deliberately did **not** adopt it. `Criticality::decision()` returns machine-readable log
  values (`crashed`, `degraded-and-continued`) rather than display text — translating them would
  corrupt the failure report. And `EndReason::isInvoluntary()` stays as `$this !== self::Left`: an
  allowlist of involuntary cases, which enumerator's `HasGrouping` would encourage, defaults a future
  case to *voluntary*, and in this domain that understates what happened to somebody's account.

  Each enum overrides `translationSlug()`. `IsTranslatable` derives it from `class_basename()` — a
  Laravel helper called with no `function_exists()` guard, the only unguarded one in that trait — so
  overriding it is what keeps these enums working with no Laravel booted, and stops a class rename
  silently relocating every translation key. A unit test with no application booted asserts every
  label still resolves.

- **The `framework-agnostic Core` claim is corrected rather than quietly retained.** Core still
  imports no `Illuminate` code and calls no framework helper — both architecture tests still pass and
  still bite — but `laranail/enumerator`'s own Composer requirements include six `illuminate/*`
  packages, so Core's *dependency tree* is no longer framework-free even though its *code* is. A
  Symfony or Slim application consuming Core would pull Illuminate in through Composer; the earlier
  claim that such a bridge could consume Core unchanged is gone from `architecture.md` and
  `comparison.md`. The `toOnlyUse` allowlist gained three closed `Enumerator\*` namespaces, so
  anything further reaching into Core is a decision rather than an accident.

  Also: `EnumeratorServiceProvider` joins the test case's provider list. Without it
  `TranslatorAdapter` is unbound, every `label()` skips the translator and falls back to its
  attribute — so a translation test would have asserted the English string and passed.

- **The cross-database test harness dropped every table except the `migrations` ledger**, leaving the
  two to disagree. A later `artisan migrate` — which the Passport test runs to build `oauth_clients`
  — read the ledger, concluded everything was applied, and created nothing; every assertion in that
  file then failed with *"relation does not exist"* on any driver that keeps state between tests. The
  ledger is now dropped with everything else. Latent since cross-database testing was added and only
  surfaced once the suite grew enough to reorder around it.

- **The doctor is nineteen `DoctorCheck` objects, and they surface in the family-wide doctor.** The
  682-line `DoctorCommand` monolith is now one class per check under `src/Laravel/Doctor/Checks/`,
  registered into package-tools' shared `DoctorService` — so
  `php artisan laranail::package-tools.doctor` reports impersonation's findings under a
  `laranail/impersonator` group alongside every other laranail package's.

  `laranail::impersonator.doctor` stays, reimplemented as a thin runner over the same objects: it is
  documented, referenced from the issue template, and unlike the shared runner it exits non-zero on a
  failure, which is what makes it usable as a CI gate. One list feeds both, so they cannot disagree.

  Fifteen checks became nineteen because four were emitting several findings from one method — the
  driver and adapter, the duration and its extension ceiling, and approval's notification and pruning
  warnings are now separately named and separately reportable. `SKIP` joins the severities, for a
  check whose precondition is absent; "not applicable" and "not checked" are different statements and
  only one is reassuring.

  The table probe now goes through db-tools' `DatabaseGuard::tableExists()`, which is non-throwing and
  self-bootstrapping — a bare `Schema::hasTable()` raises when the database is merely unreachable,
  which is a different diagnosis from "the migration has not been run" and the one an operator most
  needs told apart.

  Two things found while wiring it up. `DoctorService::register()` instantiates a class-name argument
  with a bare `new $check` — no container, no arguments — so checks taking `Settings` must be
  registered as *instances*; doing so is confined to `runningInConsole()`, since only a console
  process can run a doctor. And Testbench does not run Laravel's package discovery, so
  `PackageToolsServiceProvider` is now listed explicitly in the test case — without it `DoctorService`
  is unbound and the registration silently no-ops in tests while working in production.

- **The PHP floor moves to `^8.4.1 || ^8.5`, and four `laranail/*` packages become hard
  dependencies** — `package-tools`, `console`, `enumerator` and `db-tools`, resolved through git VCS
  repositories rather than Packagist, with the full transitive closure declared at the root (Composer
  ignores a dependency's own `repositories`).

  The floor is inherited rather than chosen: `laranail/console` declares `^8.4.1` for its optional
  `symfony/tui` integration, and Composer resolves this package to that whether or not the suggest is
  installed. **PHP 8.3 is dropped.** CI matrices move to 8.4/8.5 and Rector to the `php84` set.

  Constraints match what each repository actually has **tagged on its remote**, which is not what the
  family's `^0.1` convention would suggest: `db-tools` is at `v0.7.0`, so `^0.1` would have silently
  installed a version six minor releases behind the API this package is written against. It is
  therefore `^0.7`, while the other three are `^0.1`.

  Between them the four add only two third-party packages a Laravel application would not already
  have — `brick/money` and `spatie/laravel-sluggable`, both transitive through `db-tools` and neither
  used here. `src/Core` remains free of `Illuminate` imports; the architecture test is unchanged.

  **This now requires Symfony 8.** Laravel 13 accepts `^7.4 || ^8.0`, but `laranail/console` pins
  `symfony/console ^8.0`, so installing this package removes Symfony 7 from the resolution. An
  application deliberately held on Symfony 7 cannot take this upgrade — worth knowing, because the
  error Composer reports names `symfony/console` rather than anything in this package.

- **The compliance CSV export produced output that standards-compliant parsers corrupt.** PHP's
  historic `fputcsv` escape (`\`) is not RFC 4180 — it backslash-escapes a quote instead of doubling
  it. The `payload` column is JSON, so it is full of quotes and backslashes, and a field containing
  `say "hi"` came out as something Excel, Python's `csv` module and every other RFC parser mis-read.

  Round-tripping through PHP's own `fgetcsv` could never catch it, because that reader is symmetric
  with the writer — which is exactly why an export whose entire purpose is being read by *somebody
  else's* tooling had a bug invisible from inside PHP. Every write now passes `escape: ''`, and the
  new test parses the export back with a compliant reader and asserts each payload cell still decodes.

  Surfaced by moving Rector to the `php84` set, which flagged the deprecated implicit `$escape`. Note
  Rector's mechanical suggestion is `escape: '\'` — the legacy value, which preserves the bug.

- **Polymorphic columns are declared as morph pairs, and named for the ability rather than the role.**
  The impersonated account's columns move from `target_type` / `target_id` to
  `impersonatable_type` / `impersonatable_id` on both `impersonator_audits` and
  `impersonator_approval_requests`, matching `canBeImpersonated()` and the existing
  `ImpersonatableType`. `target` remains the name in the API, in the Core value object and on the
  `?target=` filter — those describe a request, not a column, and renaming them would break every
  client for no reason. The operator keeps `impersonator_*`: it is an actor, and an actor has no
  `-able` form. `revoked_by_*`, `decided_by_*` and `requester_*` are unchanged for the same reason.

  All six pairs are now declared through one migration helper governed by new config:

  - **`morphs.key_type`** — `string` (default), `numeric`, `uuid` or `ulid`. `string` rather than
    Laravel's `morphs()` default of `unsignedBigInteger`, because that would make the table unable to
    hold a UUID-keyed model, and holding several differently-keyed models in one trail is the point
    of a multi-model allowlist.
  - **`morphs.register_map`** (default on) — publishes `targets.allowlist` into Laravel's morph map,
    which **fixes a latent bug**: the `morphTo()` relations on both models were broken for every
    aliased type. `impersonatable_type` holds `user`, Eloquent had no map for it, and instantiating a
    class literally named `user` threw *"Class \"user\" not found"*. Nothing caught it because no
    test exercised a relation — everything else resolves aliases through `TargetRegistry`. An alias
    already in the map is never overwritten, and an entry whose alias *is* its class name is not
    published at all (it would shadow a real alias, since additions are prepended).
  - **`morphs.require_map`** (default off) — `Relation::requireMorphMap()`, so a `*_type` can never
    hold a class name. Off by default because that call is application-global: a package does not get
    to make an unrelated `commentable` start throwing on upgrade. The package's own boundary does not
    depend on it — `targets.allowlist` is deny-by-default regardless.

  Two things the helper deliberately does **not** do. It adds no index, because Laravel's
  auto-generated name for the approvals pair would be 74 characters and MySQL's identifier limit is
  64 — the migration would simply fail there — and because each table already declares the
  three-column composite that is actually queried. And it does not touch the audit hash chain: the
  chained fact stays keyed `target` with the value `type:id`, so only the columns it is read *from*
  moved and every existing row still verifies.

  Also fixes `AuditService`, which derived its column name from the public filter name — so
  `?target=user:9` queried a column that no longer existed. The two are now separate arguments.

- **RBAC detection is configurable instead of hardcoded.** Selecting `RbacPolicy` was
  `class_exists(Spatie\Permission\PermissionServiceProvider::class)` behind a hard `use` import — a
  compile-time reference to a package this one does not require, not even as a dev dependency. Two
  layers replace it: `authorization.rbac.detect`, a list of class names probed with `class_exists()`,
  and `Impersonator::detectRbacUsing(Closure)` for a rule a class list cannot express.

  Both **fail closed** — anything other than a literal `true` selects `BasePolicy`, including a truthy
  string and a thrown detector. Reading a broken detector as "this application has permissions" would
  hand `RbacPolicy` a permission system it cannot query.

  The policy was already duck-typed against `hasPermissionTo()` / `hasRole()`, so the detection list
  was the only spatie-specific thing left in the package; pointing it at another permission package is
  now genuinely all that is required. An explicit `authorization.policy` still wins over both layers.

### Fixed

- **`enter()` threw a database error on PostgreSQL whenever a concurrency cap was configured — which
  it is by default.** `EloquentAuditStore::open()` guarded its count-then-insert with
  `SELECT count(*) … FOR UPDATE`, and PostgreSQL rejects that outright: *"FOR UPDATE is not allowed
  with aggregate functions"*. So the cap did not merely fail to lock there, it raised a
  `QueryException` on every impersonation. The same applied to the `deny_when_target_busy` check via
  `exists()`, which compiles to the same aggregate context. Both now select locked ids and count them
  in PHP, which holds the lock on every driver. **The package was unusable on PostgreSQL before this.**
- **`read_only` mode blocked Laravel's own session write on PostgreSQL and MySQL**, refusing every
  request. `PersistenceGuard::tableFrom()` stopped at the first identifier delimiter, so
  `update "public"."sessions"` parsed as table `public`, never matched its exemption, and the guard
  denied the framework's session persistence. It now reads the whole dotted chain, strips each
  driver's quoting (`"pg"`, `` `mysql` ``, `[sqlsrv]`, bare), and matches an exempt entry written in
  either the qualified or unqualified form. `deny_models` was failing the same way.

### Changed

- **The test suite can run against PostgreSQL and MySQL**, via `IMPERSONATOR_TEST_DB=pgsql|mysql`.
  Both bugs above existed because the suite ran SQLite only: it emits unqualified table names, so the
  parsing defect never surfaced, and it compiles `lockForUpdate()` to an empty string, so the
  aggregate-with-lock combination never executed.
- **Tests that assert atomicity now skip loudly rather than passing on a driver that cannot prove
  them.** `SQLiteGrammar::compileLock()` returns `''`, so every claim about the concurrency cap and
  the chain-head lock was previously green without exercising a lock at all. The new `locking` group
  names the driver in its skip message and passes on PostgreSQL.

### Security

- The `APP_KEY` literal is gone from `phpunit.xml`; `tests/TestCase.php` generates one per run. It was
  a real fixture rather than a real secret — it encrypted only in-memory test sessions, and it was the
  only version of that file ever committed — but it was a structurally valid AES-256 key, so secret
  scanners were right to flag it. Generating it removes the detector surface instead of suppressing
  the alert. A scan of every blob in the object database, reachable and unreachable, found nothing
  else; no rotation or history rewrite was required.

### Fixed

- **The persistence-level mode guard outlived its request.** `DB::beforeExecuting` has no removal
  counterpart, so the listener stayed armed after the response — and closing an impersonation is an
  `UPDATE` on the audit row. A `read_only` guard denied it, so **an operator could not leave**,
  which is the one outcome the mode must never produce. Under Octane or a queue worker the listeners
  also accumulated, each enforcing a stale impersonation. Now one listener is registered at boot and
  consults a `PersistenceGuard` the middleware arms for the request and disarms in `finally`.
- **The guard judged the package's own bookkeeping as user writes.** The audit row, the action
  trail, handoff tokens and approvals are all written *while* an impersonation is in flight, and
  Laravel writes its session and cache tables on ordinary reads — with `SESSION_DRIVER=database`,
  every request. Those tables are now exempt (configurable via `modes.exempt_tables`). The queue
  tables are deliberately **not** exempt: a job dispatched from a read-only session is a write with
  a delay on it.
- **`modes.limited.deny_models` never matched anything.** It holds class names, but the persistence
  guard — the only layer that can tell which model a write touches — reports the *table*. Comparing
  the two never matched, so a configured deny-list read as protection while enforcing nothing. Both
  forms now resolve.
- **Session contents crossed the impersonation boundary in both directions.** Rotating the session
  id preserves its attributes, so the operator's cart, half-finished form or flashed data travelled
  into the impersonated session, and the target's travelled back out on leave. Now flushed on both
  transitions (`session.flush_on_switch`, on by default), preserving the operator's own auth key
  when they sit on a different guard, and minting a fresh CSRF token.
- **Leaving rotated the target's `remember_token`.** `SessionGuard::logout()` cycles it, so an
  operator finishing a support session logged the real customer out of every device they owned and
  invalidated a recaller cookie set weeks earlier. Leaving now forgets the guard's session key and
  its cached user, and nothing else.
- The published package shipped **two copies of `helpers.php`** — one inside the PSR-4 source root,
  which was the autoloaded one — and documented the `read_only` persistence guard, the `limited`
  deny-lists, the adapter TTL/ability/scope keys and the rate-limit decay under names that did not
  exist in the config file.

### Changed

- **`modes.read_only.prevent_writes` now defaults to on.** A mode named read_only that permits a
  write behind a GET route, a queued job, a Livewire action or a raw query is not read-only, and the
  guarantee is the entire reason to offer the mode. The usual objection to a persistence guard —
  that aborting mid-request can strand earlier writes — does not apply when *every* write is denied:
  the first one aborts and there is nothing half-done behind it.

### Security

- `Referrer-Policy: no-referrer` and `Cache-Control: no-store` on the accept response, so a URL
  carrying a live single-use token does not travel onward as a referrer or rest in a shared cache.
  Documented the log-retention channel, which is the significant one — including Telescope, which
  records the full URI of a *failed* request, precisely when the token may still be unspent.

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
- **Complete event surface** (15 events): adds `ImpersonationRequested`,
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
- **`laranail::impersonator.doctor`** — twenty-one checks for the things that are wrong *silently*,
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

- Both documented ways to reach the facade are pinned by a test: the auto-registered
  `Impersonator` alias from `extra.laravel.aliases`, and the explicit
  `ImpersonatorFacade as Impersonator` import. Nothing in the suite had exercised the published
  alias, and a clean-install smoke test in a fresh Laravel app caught the README naming a class
  that does not exist. That smoke test — `composer require` from the tag, publish, migrate, run
  the doctor, perform a real impersonation — is now a documented pre-release step.

### Fixed

- `LeaveImpersonation` re-reads the audit row after closing it, so a caller learns *how* it ended.
  It previously returned the snapshot taken before the close, which meant an API response reported
  a null `ended_by` for a completed leave — a response contradicting itself.
- The audit listing endpoint 404s for an id that matches nothing, rather than surfacing
  `AuditRowMissing`. That exception means state was lost between opening a row and acting on it,
  which is a bug signal; an id typed by a client is an ordinary not-found.

### Security

- Every GitHub Action is pinned to a full commit SHA with a trailing version comment, every job
  sets `timeout-minutes`, and checkout runs with `persist-credentials: false` since no job pushes
  with the token. A moved tag is how the tj-actions compromise spread.
- CodeQL runs over the `actions` language, scanning the workflows themselves. CodeQL has no PHP
  support, so PHPStan at level max with no baseline remains the SAST for the package.
- Dependency Review runs on pull requests, failing on moderate severity and denying the copyleft
  licences that would change the terms consumers of an MIT package receive it under.
- OpenSSF Scorecard runs weekly and on branch-protection changes, with results published.
- Dependabot groups the dev toolchain and the optional integrations, so a week of updates arrives
  as two reviewable pull requests rather than nine.

[0.1.0]: https://github.com/laranail/impersonator/releases/tag/v0.1.0
[Unreleased]: https://github.com/laranail/impersonator/compare/v0.1.0...HEAD
