<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Values\Mode;

return [

    /*
    |--------------------------------------------------------------------------
    | Master switch
    |--------------------------------------------------------------------------
    | Turning this off refuses every impersonation attempt with a `disabled`
    | decision while leaving routes, audit reads and the API intact — so an
    | incident responder can stop new impersonations without a deploy, and
    | still read the trail of the ones that already happened.
    */

    'enabled' => env('IMPERSONATOR_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Driver — how the impersonator reaches the target's context
    |--------------------------------------------------------------------------
    | One of the two orthogonal axes. Composed freely with any adapter below.
    |
    |   session  Same application. Nothing crosses a domain boundary.
    |   token    Cross-domain or cross-subdomain, via a single-use hashed token.
    |   tenancy  Delegates to stancl/tenancy's own handoff. Registered only when
    |            stancl/tenancy is installed.
    |   auto     tenancy when a tenant is initialized, session otherwise.
    |
    | An explicit value always wins over `auto`.
    */

    'driver' => env('IMPERSONATOR_DRIVER', 'session'),

    /*
    |--------------------------------------------------------------------------
    | Adapter — how the target gets authenticated
    |--------------------------------------------------------------------------
    | The other axis. `session` covers every stateful guard, including Sanctum's
    | SPA cookie mode.
    |
    | For the three API adapters, impersonation means issuing a short-lived
    | credential scoped to impersonation and returned exactly once. It cannot be
    | retrieved again afterwards: only its SHA-256 digest is stored.
    |
    | Each non-session adapter registers only when its package is installed.
    */

    'adapter' => env('IMPERSONATOR_ADAPTER', 'session'),

    /*
    |--------------------------------------------------------------------------
    | Adapter settings
    |--------------------------------------------------------------------------
    | Each API adapter issues a credential for the target rather than switching a
    | session. Lifetimes are deliberately their own settings rather than inherited from
    | the host package: a support credential and a user's own long-lived API token have
    | nothing in common, and inheriting would routinely produce an impersonation token
    | valid for weeks.
    |
    | The scope/ability is a single named one rather than `*`, so an application can
    | refuse anything it considers off-limits to an impersonated caller.
    */

    'adapters' => [

        'sanctum' => [
            'ability' => 'impersonated',
            'expires_after' => env('IMPERSONATOR_SANCTUM_TTL', 15),
        ],

        'passport' => [
            'scope' => 'impersonated',
            'expires_after' => env('IMPERSONATOR_PASSPORT_TTL', 15),
            // A refresh token is never issued. It would let an impersonation renew itself
            // indefinitely, outliving both its audit row and the operator's authority to
            // hold it. Not configurable, by design.
        ],

        'jwt' => [
            'ttl' => env('IMPERSONATOR_JWT_TTL', 15),
            // Claims written into every impersonation token: imp_by, imp_audit, imp_mode.
            // The mode is included so a resource server that has never heard of this
            // package can still refuse a write from a read_only impersonation.
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Guards
    |--------------------------------------------------------------------------
    | These are frequently different guards: an operator authenticated on
    | `admin` enters, and the target is logged in on `web`. Both are validated
    | against config('auth.guards') on every request, so a typo fails at the
    | boundary rather than silently authenticating against the wrong provider.
    */

    'guards' => [
        'impersonator' => env('IMPERSONATOR_GUARD', 'web'),
        'target' => env('IMPERSONATOR_TARGET_GUARD', 'web'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Polymorphic columns
    |--------------------------------------------------------------------------
    | Every participant this package records is polymorphic — the operator, the
    | impersonated account, whoever revoked or approved — so the tables store a
    | morph pair (`*_type` + `*_id`) rather than a foreign key. The `*_type`
    | half holds a **morph alias**, never a class name, which is what stops a
    | crafted `target_type` from naming an arbitrary class.
    */

    'morphs' => [

        // How the `*_id` half is stored.
        //
        //   'string'  — the default. One audit table can hold an int-keyed User
        //               and a UUID-keyed Vendor side by side, which is the whole
        //               point of a multi-model allowlist. Comparisons are
        //               type-loose in Identity to match.
        //   'numeric' — unsignedBigInteger. Smaller and faster, but every
        //               impersonatable model must then use integer keys.
        //   'uuid'    — char(36). Every model must use UUIDs.
        //   'ulid'    — char(26). Every model must use ULIDs.
        //
        // Only read when the migration runs. Changing it afterwards needs a
        // migration of your own; the package will not silently rewrite columns.
        'key_type' => env('IMPERSONATOR_MORPH_KEY_TYPE', 'string'),

        // Publish `targets.allowlist` into Laravel's own morph map at boot, so
        // Eloquent can resolve an alias back to a class.
        //
        // On by default because without it the package's `morphTo()` relations
        // cannot work: the column holds `user`, and Eloquent with no map for it
        // tries to instantiate a class named `user`. The aliases published are
        // the ones you configured in `targets.allowlist` — nothing invented.
        //
        // An alias already present in the morph map is never overwritten.
        // Repointing one would change which class every historic row resolves
        // to, application-wide.
        'register_map' => env('IMPERSONATOR_REGISTER_MORPH_MAP', true),

        // Refuse to resolve a polymorphic type that has no morph alias, by
        // calling Relation::requireMorphMap() at boot.
        //
        // Off by default, and the reason is scope rather than caution: that call
        // is **application-global**. Turning it on here makes *your* unmapped
        // morphs throw too, anywhere in your application — which is a good
        // practice, but not one a package gets to switch on for you.
        //
        // This package already enforces aliases on its own boundary regardless:
        // `targets.allowlist` is deny-by-default, so an unaliased class cannot
        // be impersonated whatever this is set to. Enabling it buys defence in
        // depth for the columns, not the primary control.
        'require_map' => env('IMPERSONATOR_REQUIRE_MORPH_MAP', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Modes
    |--------------------------------------------------------------------------
    | Every impersonation carries a mode, chosen once at enter time and stored
    | server-side in both the session and the audit row. It is never read back
    | from client input, so there is no mid-session escalation path: changing
    | mode means leaving and re-entering.
    |
    | `default_mode` ships as `full` for parity with the existing packages in
    | this space. `limited` is the recommended production value — see
    | docs/tools/modes.md. The doctor command warns when `full` is the default.
    */

    'default_mode' => env('IMPERSONATOR_DEFAULT_MODE', Mode::FULL),

    'modes' => [

        'read_only' => [
            // Unsafe methods are refused with 403. Leaving and logging out stay
            // reachable — a mode that could trap an operator inside an account
            // would be worse than no mode at all.
            'allowed_methods' => ['GET', 'HEAD', 'OPTIONS'],

            'allowed_routes' => [
                'impersonator.leave',
                'impersonator.extend',
                'logout',
            ],

            // Intercept writes at the persistence layer, not just by HTTP method.
            //
            // On by default, because method checking alone cannot see a write reached
            // through a GET route, a queued job, a Livewire action or a raw query — and a
            // mode named `read_only` that permits any of those is not read-only.
            //
            // The usual objection to a persistence guard is that aborting mid-request can
            // leave partial work behind. That does not apply here: in this mode *every*
            // write is denied, so the first one is the one that aborts and there is no
            // earlier write to leave half-done. (It is a real consideration for `limited`,
            // where some writes pass — which is why the model deny-list there turns the
            // guard on only when it is actually configured.)
            //
            // Turn it off only if you have a specific incompatibility, and know that
            // read_only then bounds HTTP methods alone.
            'prevent_writes' => env('IMPERSONATOR_READ_ONLY_PREVENT_WRITES', true),
        ],

        'limited' => [
            // Writes are allowed except these. Defaults cover the account
            // takeover paths an impersonated session should never reach.
            'deny_routes' => [
                'password.update',
                'password.confirm',
                'profile.destroy',
                'two-factor.enable',
                'two-factor.disable',
            ],

            'deny_paths' => [
                'billing/*',
                'settings/password',
                'settings/two-factor*',
                'user/confirm-password',
                'user/two-factor-*',
            ],

            // Livewire actions, as `Component::method`.
            //
            // A separate axis because `deny_routes` and `deny_paths` **cannot see**
            // a Livewire action: every one of them POSTs to a single endpoint with
            // the component and method in the payload, so from the outside they
            // are indistinguishable. A rule naming a route matches nothing there,
            // and a rule broad enough to match blocks the whole application.
            //
            // Patterns use the same `Str::is` matching as deny_routes, against the
            // qualified name, the bare component and the bare method:
            //
            //   'ProfileForm::updatePassword'   one action
            //   'ProfileForm::*'                a whole component
            //   '*::destroy'                    a method wherever it appears
            //
            // Empty by default, like deny_models: the component names are the
            // application's own and this package cannot guess them. Reading the
            // payload costs nothing until you configure something here.
            //
            // `read_only` needs none of this — its guard is at the persistence
            // layer and does not care how the request arrived.
            'deny_livewire' => [],

            'deny_abilities' => [
                'delete-account',
                'update-password',
                'manage-billing',
            ],

            'deny_models' => [
                // App\Models\PaymentMethod::class,
            ],
        ],

        'full' => [
            // Everything the target can do. No additional configuration.
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Targets
    |--------------------------------------------------------------------------
    | Targets resolve only through this allowlist. Without it, an endpoint that
    | accepts a class name as input lets a caller name any Eloquent model and
    | have the package load it — so an empty allowlist denies everything rather
    | than allowing anything.
    |
    | Keys are the morph alias stored in the audit row; values are the class.
    | Registering them with Relation::enforceMorphMap() as well is recommended.
    |
    | MORE THAN ONE MODEL IS SUPPORTED, and is the normal case for anything beyond a
    | single-model app — a marketplace has customers and vendors, a B2B product has staff
    | and tenant admins. Each entry may be either:
    |
    |   'alias' => Model::class                      the simple form
    |
    |   'alias' => [                                 when the model needs its own settings
    |       'model' => Model::class,
    |       'guard' => 'vendor',                     defaults to guards.target
    |       'display_name' => 'company_name',        defaults to banner.display_name
    |       'label' => 'Vendor account',             shown in a type picker
    |   ]
    |
    | `guard` is the one that matters: models on different guards cannot share a single
    | global target guard, and authenticating a vendor against the customer provider would
    | either fail confusingly or find a different account with the same id.
    |
    | A package can also register a type at runtime, without the host editing this file:
    |
    |   Impersonator::registerTarget('vendor', Vendor::class, guard: 'vendor');
    */

    'targets' => [

        // A per-instance rule about the target, on top of the allowlist.
        //
        // The allowlist answers *which models*; soft deletes are the only per-row
        // rule this package knows. GitLab additionally refuses blocked,
        // password-expired, internal and bot accounts — states this package
        // cannot know about, so this is where you express them:
        //
        //   'eligibility' => fn (Model $target): bool => ! $target->is_blocked,
        //
        // A closure, an invokable class name, or null. Fails closed on anything
        // but a literal true, including a thrown exception.
        'eligibility' => null,
        'allowlist' => [
            'user' => 'App\Models\User',

            // A second model, with its own guard and label:
            // 'vendor' => [
            //     'model' => 'App\Models\Vendor',
            //     'guard' => 'vendor',
            //     'display_name' => 'company_name',
            //     'label' => 'Vendor account',
            // ],
        ],

        // Soft-deleted targets are refused by default: an account someone
        // deleted is not one support should be operating inside.
        'allow_soft_deleted' => env('IMPERSONATOR_ALLOW_SOFT_DELETED', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Authorization
    |--------------------------------------------------------------------------
    | Always active: the canImpersonate() / canBeImpersonated() model hooks, the
    | `impersonate` gate ability when one is defined, and refusal of
    | self-impersonation and nesting.
    |
    | The `permissions` and `roles` blocks additionally apply when
    | spatie/laravel-permission is installed, and are ignored when it is not.
    */

    'authorization' => [

        // Which policy decides. Null auto-selects: the RBAC policy when a
        // permission package is installed, the base policy otherwise. Set a class name
        // to take over entirely — extend BasePolicy or RbacPolicy rather than
        // reimplementing, so the always-on identity rules cannot be lost by accident.
        'policy' => null,

        // How the RBAC policy is auto-selected when `policy` above is null.
        //
        // A list of class names probed with class_exists(). The first one present
        // selects RbacPolicy. Defaults to spatie/laravel-permission's provider
        // because that is the package the policy was written against — but only as
        // a default: the policy is duck-typed against hasPermissionTo() and
        // hasRole(), so any package exposing that surface works once named here.
        //
        // Detected by provider class rather than by a trait on the user model: the
        // model may not be loaded this early, and a provider's presence is the
        // reliable signal the package is wired in rather than merely in vendor/.
        //
        // For a rule a class list cannot express, register a closure instead:
        //
        //   Impersonator::detectRbacUsing(fn (): bool => MyPermissions::enabled());
        //
        // Either way detection fails closed — anything but a literal true selects
        // BasePolicy, which still enforces every identity rule.
        //
        // Plain strings, not `::class`: this file is published into your
        // application, and a `::class` reference to a package you may not have
        // installed is an unknown class to your own static analysis.
        'rbac' => [
            'detect' => [
                'Spatie\\Permission\\PermissionServiceProvider',
            ],
        ],

        'gate_ability' => 'impersonate',

        // Re-check the operator's permission on **every** impersonated request,
        // not only at enter.
        //
        // Off by default because it costs a permission lookup per request, which
        // on an RBAC package backed by the database is not free (it is memoised
        // per request, so a route hitting the middleware twice pays once).
        //
        // Turn it on where losing a role should end live sessions immediately.
        // Without it, revoking an operator's access leaves their impersonations
        // running until the duration cap — so the withdrawal that mattered most
        // is the one that takes effect last.
        'recheck_each_request' => env('IMPERSONATOR_RECHECK_EACH_REQUEST', false),

        // Require a recent password confirmation before entering.
        //
        // The strongest operator-side control here, and what GitLab's Admin Mode
        // exists to provide: re-authenticate, then a bounded window. ASVS 7.5.3
        // treats entering impersonation as a highly sensitive operation — without
        // this, a stolen session cookie reaches every account in the system.
        //
        // **Off by default because it needs a host-side flow.** `session_key`
        // reads the stamp Laravel's own `password.confirm` route writes; turn
        // this on without routing operators through that first and every
        // impersonation is refused.
        //
        // Refuses on an absent timestamp as well as a stale one — an install that
        // forgot the flow produces exactly the absent case.
        'step_up' => [
            'require' => env('IMPERSONATOR_REQUIRE_STEP_UP', false),
            'within' => env('IMPERSONATOR_STEP_UP_WITHIN', 900),
            'session_key' => 'auth.password_confirmed_at',
        ],

        // Nesting is refused: an impersonated session must not be able to reach
        // a third account, or the audit trail stops describing who acted.
        'allow_nested' => false,

        'permissions' => [
            'enter' => 'impersonator.enter',

            // Interpolated per mode: impersonator.mode.read_only, and so on.
            // This is what pins junior staff to read_only.
            'mode' => 'impersonator.mode.%s',

            'revoke' => 'impersonator.revoke',
            'approve' => 'impersonator.approve',
            'audit_view' => 'impersonator.audit.view',
        ],

        'roles' => [
            // Holders of these roles can never be impersonated, by anyone.
            'protected' => ['super-admin'],

            // Optional hierarchy rule. Null uses the built-in check: the
            // impersonator's highest role level must exceed the target's.
            // May be a closure or an invokable class name.
            'hierarchy' => null,

            // Role name to level, for the built-in hierarchy check.
            'levels' => [
                'super-admin' => 100,
                'admin' => 80,
                'manager' => 60,
                'support' => 40,
                'user' => 10,
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Reason
    |--------------------------------------------------------------------------
    | Turning `require` on refuses an enter without a stated reason. Recommended
    | wherever impersonation touches customer data.
    */

    'reason' => [
        'require' => env('IMPERSONATOR_REQUIRE_REASON', false),
        'min_length' => 3,
        'max_length' => 500,
    ],

    /*
    |--------------------------------------------------------------------------
    | Limits
    |--------------------------------------------------------------------------
    */

    'limits' => [
        // Concurrent impersonations one operator may hold. Enforced inside a
        // locked transaction, since a plain count-then-insert is a race.
        'max_active_per_impersonator' => env('IMPERSONATOR_MAX_ACTIVE', 1),

        // Refuse entering a target somebody else is already impersonating.
        'deny_when_target_busy' => env('IMPERSONATOR_DENY_WHEN_BUSY', false),

        // Minutes before an active impersonation is force-ended as `expired`.
        // Null means unlimited, which is not recommended: the doctor command
        // warns about it.
        //
        // Ten minutes because exposure should be measured in the length of the
        // task, not the length of a shift. Most support work inside an account
        // is a couple of minutes of looking; the sessions that run for an hour
        // are usually the ones nobody remembered to close. Where the work does
        // take longer, `extension` below is the way to say so explicitly.
        'max_duration' => env('IMPERSONATOR_MAX_DURATION', 10),

        // Minutes of inactivity before an impersonation is force-ended. Null is
        // off, which is the default.
        //
        // Separate from max_duration, which is absolute. An impersonation
        // abandoned mid-session is exactly the row that turns up in an audit with
        // no explanation, and an absolute cap alone leaves it open for the full
        // window. Tracked in the session, so it costs no query.
        'max_idle' => env('IMPERSONATOR_MAX_IDLE'),

        // Buying more time from inside a live impersonation.
        //
        // The escape valve that lets `max_duration` stay short. Without it the
        // pressure is to raise the window "just in case", and a long window is
        // exactly what a short one is for — so instead the default is small and
        // staying longer is a decision, recorded as one.
        //
        // Two independent bounds apply and the stricter wins: `max` limits how
        // many times, `max_total_duration` limits how long in total. Both are
        // needed. A count alone bounds nothing when the window is configurable;
        // a total alone never asks the operator to re-justify.
        'extension' => [
            'enabled' => env('IMPERSONATOR_EXTENSION_ENABLED', true),

            // Minutes added per extension.
            'minutes' => env('IMPERSONATOR_EXTENSION_MINUTES', 10),

            // How many extensions per impersonation. Null is unlimited, which
            // makes `max_duration` advisory — prefer a ceiling instead.
            'max' => env('IMPERSONATOR_EXTENSION_MAX', 3),

            // The hard ceiling, in minutes from the moment it started. Nothing
            // extends past this; the last extension is clamped to it rather
            // than refused, so the whole allowance is usable. Null removes the
            // ceiling, and with it the guarantee that the window is bounded.
            'max_total_duration' => env('IMPERSONATOR_MAX_TOTAL_DURATION', 60),

            // Only allow extending inside the final N minutes. Null allows it
            // at any time. Set it to stop an operator stacking the full
            // allowance the moment they enter, which would turn a ten-minute
            // default into an hour before any work started.
            'within' => env('IMPERSONATOR_EXTENSION_WITHIN', null),
        ],

        // How the max_duration and revocation checks avoid a per-request query.
        'state_cache' => [
            'store' => env('IMPERSONATOR_CACHE_STORE'),
            'ttl' => 30,
            'prefix' => 'impersonator:state:',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate limiting
    |--------------------------------------------------------------------------
    | `enter` is keyed by impersonator, so one operator cannot enumerate
    | accounts. `accept` is keyed by IP and throttles token redemption.
    */

    'rate_limiting' => [
        'enter' => ['attempts' => 5, 'decay' => 60],
        'accept' => ['attempts' => 10, 'decay' => 60],
        'api' => ['attempts' => 30, 'decay' => 60],
    ],

    /*
    |--------------------------------------------------------------------------
    | Handoff tokens (token driver)
    |--------------------------------------------------------------------------
    | 40 bytes from random_bytes, stored as a SHA-256 digest and looked up by
    | it, single-use, redeemed atomically. The plaintext exists only in the
    | accept URL and is never logged.
    |
    | A plain digest is correct here rather than a password hash: the value is
    | already high-entropy, so there is nothing to brute-force and no reason to
    | pay bcrypt on every redemption.
    */

    'tokens' => [
        'bytes' => 40,
        'ttl' => env('IMPERSONATOR_TOKEN_TTL', 60),
        'table' => 'impersonator_tokens',
        'connection' => env('IMPERSONATOR_TOKEN_CONNECTION'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Session behaviour
    |--------------------------------------------------------------------------
    */

    'session' => [
        'key' => 'impersonator',

        // Regenerated on both enter and leave, so neither transition leaves a
        // session id that was valid at a different privilege level.
        'regenerate' => true,

        // Clear the session's *contents* on every switch, not just its id.
        //
        // Rotating the id alone leaves `$attributes` intact, so whatever the operator had in
        // their session travels into the impersonated one and whatever the target accumulates
        // travels back out on leave — a cart, a half-finished form, flashed data. That is a
        // cross-account leak in both directions, so this is on by default.
        //
        // Turn it off only if the operator's session holds something they must keep across a
        // switch, and understand that the target then inherits it.
        'flush_on_switch' => env('IMPERSONATOR_FLUSH_SESSION_ON_SWITCH', true),

        // Never remembered. A remember-me cookie would outlive the
        // impersonation and silently resurrect it.
        'remember' => false,

        // Authenticate the target without firing the app's Login listeners — an
        // impersonated login is not the target signing in, and treating it as
        // one sends them "new login" mail and pollutes last-login columns.
        'silent_login' => true,

        // On revocation, destroy the target's session record immediately rather than
        // waiting for their next request. Works for every server-side driver (file,
        // database, redis, memcached); `array` and `cookie` keep no server-side record,
        // so those fall back to the enforcement middleware. The doctor command reports
        // which behaviour your driver gives you.
        'destroy_on_revoke' => env('IMPERSONATOR_DESTROY_ON_REVOKE', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Session-level audit
    |--------------------------------------------------------------------------
    | One row per impersonation. Append-only from the package's perspective: the
    | only mutations are the terminal transitions.
    */

    'audit' => [
        'table' => 'impersonator_audits',
        'connection' => env('IMPERSONATOR_AUDIT_CONNECTION'),

        // Days to retain, via MassPrunable. Null keeps rows forever. Child
        // trail events are pruned with their parent.
        'retention_days' => env('IMPERSONATOR_RETENTION_DAYS'),

        // Tamper evidence: each row stores a keyed digest over the previous
        // row's digest and its own payload, verified by the verify-audit
        // command. Keyed with HMAC rather than a bare hash — a plain chain is
        // recomputable by anyone holding the algorithm, which means anyone with
        // write access to the table.
        'tamper_evident' => env('IMPERSONATOR_TAMPER_EVIDENT', false),
        'hash_key' => env('IMPERSONATOR_AUDIT_HASH_KEY'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Action-level trail
    |--------------------------------------------------------------------------
    | One row per request made while impersonating — the difference between
    | knowing an operator was in an account and knowing what they did there.
    */

    'trail' => [
        'enabled' => env('IMPERSONATOR_TRAIL_ENABLED', true),
        'table' => 'impersonator_audit_events',

        // Off by default: request bodies are the likeliest place for personal
        // data to end up permanently recorded. Redaction applies when on, but
        // redaction is a filter, not a guarantee.
        'record_payloads' => env('IMPERSONATOR_TRAIL_PAYLOADS', false),

        // Applied recursively, matched case-insensitively as substrings.
        'redact' => [
            'password',
            'password_confirmation',
            'token',
            'secret',
            'authorization',
            'api_key',
            'card',
            'cvv',
            'cvc',
            'ssn',
        ],

        // 1.0 records everything. Lower it on high-traffic apps; writes are
        // always sampled per request, never per session, so a sampled trail
        // still spans the whole impersonation.
        'sample_rate' => env('IMPERSONATOR_TRAIL_SAMPLE_RATE', 1.0),

        // Never recorded, at any sample rate.
        'ignore_paths' => [
            'livewire/*',
            'telescope/*',
            'horizon/*',
            '_debugbar/*',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Causer attribution
    |--------------------------------------------------------------------------
    | During impersonation auth()->user() is the target, so activity-log
    | packages blame the target for the operator's actions. Applied when
    | spatie/laravel-activitylog or owen-it/laravel-auditing is installed.
    |
    |   impersonator  The operator is the causer. Correct, and the default.
    |   target        Legacy behaviour, if a report depends on it.
    |   both          Operator as causer, target recorded in properties.
    */

    'causer' => [
        'strategy' => env('IMPERSONATOR_CAUSER_STRATEGY', 'impersonator'),
        'property_key' => 'impersonated_target',
    ],

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    | The accept and leave routes. When the token driver runs behind a tenancy
    | package, `middleware` must include that package's identification
    | middleware or these routes resolve centrally and do nothing.
    */

    'routes' => [
        'register' => env('IMPERSONATOR_REGISTER_ROUTES', true),
        'middleware' => ['web'],
        'prefix' => 'impersonator',
        'name_prefix' => 'impersonator.',
        'accept_path' => 'accept/{token}',
        'leave_path' => 'leave',
        'enter_path' => 'enter',
        'extend_path' => 'extend',
        'revoke_path' => 'revoke/{audit}',

        // Middleware the package's own enforcement installs. Append these to your
        // `web` group (or to whichever group impersonated traffic passes through) so
        // modes, revocation and the trail apply to your application's routes too —
        // registering them only on the package's routes would enforce nothing.
        //
        // Order matters: lifetime first, because there is no point judging what a
        // terminated session may do.
        'enforcement' => [
            'impersonator.lifetime',
            'impersonator.mode',
            'impersonator.trail',
        ],

        // Automatically push the enforcement middleware onto these groups. Set to an
        // empty array to wire them yourself.
        'auto_append_to_groups' => ['web'],
    ],

    /*
    |--------------------------------------------------------------------------
    | URL building (token driver)
    |--------------------------------------------------------------------------
    | How an accept URL is addressed. Override entirely with
    | Impersonator::resolveAcceptUrlUsing() for schemes this cannot express.
    */

    'urls' => [
        // domain | subdomain | path
        'strategy' => env('IMPERSONATOR_URL_STRATEGY', 'domain'),
        'scheme' => env('IMPERSONATOR_URL_SCHEME', 'https'),
        'port' => env('IMPERSONATOR_URL_PORT'),

        // subdomain strategy: {tenant}.example.com
        'base_domain' => env('IMPERSONATOR_BASE_DOMAIN'),

        // path strategy: example.com/{tenant}/...
        'path_prefix' => env('IMPERSONATOR_PATH_PREFIX'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Redirects
    |--------------------------------------------------------------------------
    | Relative paths only by default. Every redirect target the package emits
    | passes through this: an accept-route redirect, a leave redirect and a
    | caller-supplied redirectTo are all attacker-influenceable, and an open
    | redirect on an impersonation endpoint is a credential-phishing primitive.
    */

    'redirects' => [
        'after_enter' => '/',
        'after_leave' => '/',

        'allow_absolute' => env('IMPERSONATOR_ALLOW_ABSOLUTE_REDIRECTS', false),

        // Hosts an absolute URL may point at when the above is on. Exact
        // matches; no wildcards, no suffix matching.
        'allowed_hosts' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Banner
    |--------------------------------------------------------------------------
    | Displays who is impersonating whom, the active mode, and a leave control.
    | An impersonated session that does not announce itself is how an operator
    | forgets they are in a customer's account.
    */

    'banner' => [
        'enabled' => env('IMPERSONATOR_BANNER', true),

        // auto | light | dark
        'theme' => env('IMPERSONATOR_BANNER_THEME', 'auto'),

        // top | bottom
        'position' => env('IMPERSONATOR_BANNER_POSITION', 'bottom'),

        // Attribute or accessor used to label the target. May also be a closure
        // set at runtime through Impersonator::displayNameUsing().
        'display_name' => 'name',

        'show_mode' => true,
        'show_duration' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | REST API
    |--------------------------------------------------------------------------
    | Off by default. When on, list responses never contain a credential or a
    | credential hash — a digest is still a verifier for a guessed token.
    */

    'api' => [
        'enabled' => env('IMPERSONATOR_API_ENABLED', false),
        'prefix' => 'impersonator/api/v1',
        'middleware' => ['api', 'auth:sanctum'],
        'name_prefix' => 'impersonator.api.',
        'per_page' => 25,
        'max_per_page' => 100,
    ],

    /*
    |--------------------------------------------------------------------------
    | Notifications
    |--------------------------------------------------------------------------
    | Both off by default — enabling either changes what your users receive.
    */

    'notifications' => [
        // Tell the target their account was accessed. A transparency and GDPR
        // posture choice, not a security control.
        'notify_target' => env('IMPERSONATOR_NOTIFY_TARGET', false),

        // Channels for the target's disclosure notice. `database` needs Laravel's
        // notifications table; `mail` needs the model to be routable.
        'target_channels' => ['mail'],

        // Seconds to hold the notice back. Not throttling — it lets disclosure land
        // after a short support interaction rather than mid-conversation.
        'notify_target_delay' => 0,

        'security_channel' => [
            'enabled' => env('IMPERSONATOR_SECURITY_ALERTS', false),
            'mail' => [],
            'webhook' => env('IMPERSONATOR_SECURITY_WEBHOOK'),

            // Which lifecycle events raise an alert.
            'on' => ['full_mode_enter', 'revoked'],
        ],

        // Break-glass approvals. Only relevant when `approval.require` is on.
        'approvals' => [
            'enabled' => env('IMPERSONATOR_NOTIFY_APPROVERS', false),

            // Who to ask. Plain mail addresses work with no further setup; the
            // `resolver` is for notifying real users — a closure or invokable class
            // name receiving the ApprovalRequest and returning notifiables (models,
            // a Collection, or anything with `notify()`).
            //
            // This package cannot find your approvers itself: it is duck-typed
            // against an RBAC surface rather than depending on one, so it has no way
            // to query "everybody holding impersonator.approve".
            'mail' => [],
            'resolver' => null,

            // Tell the requester the outcome — approved, denied, or nobody answered.
            // An operator left wondering which of the three happened will ask a
            // colleague to approve it out of band, which is how a control gets
            // routed around.
            'notify_requester' => true,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Approval workflow
    |--------------------------------------------------------------------------
    | A break-glass flow, deliberately minimal: entering creates a pending
    | request that a second authorized operator approves. Not a workflow engine.
    */

    'approval' => [
        'require' => env('IMPERSONATOR_REQUIRE_APPROVAL', false),
        'table' => 'impersonator_approval_requests',
        'decisions_table' => 'impersonator_approval_decisions',

        // Minutes before an unapproved request expires.
        'ttl' => 15,

        // How many reviewers a request needs, per mode, falling back to `default`.
        //
        // Four semantics, each chosen rather than fallen into:
        //
        //  - **A single denial is terminal.** Approvals accumulate; one refusal
        //    ends the request. A reviewer who spots a problem should not have to
        //    persuade the others first, and failing closed is the only safe
        //    reading of a disagreement about access to somebody's account.
        //  - **One reviewer fills at most one role slot.** Otherwise somebody
        //    holding both `manager` and `auditor` satisfies a two-role policy
        //    alone, and the separation of duties is theatre.
        //  - **The requirement is max(quorum, sum of roles).** `quorum` is an
        //    independent floor, not something the role map silently overrides: the
        //    `full` policy below needs two reviewers, one of each role.
        //  - **`quorum` is floored at 1.** A zero would mean "approval required"
        //    and "nothing required" at once.
        //
        // Roles are matched against the model's own `hasRole()` / `getRoleNames()`
        // — the same duck-typed surface the RBAC policy uses, so no hard
        // dependency and any permission package works.
        'policies' => [
            'default' => ['quorum' => 1, 'roles' => []],
        ],

        // An extra per-request check on a reviewer, for a rule config cannot
        // express — "must be the requester's line manager", say. A relationship
        // this package should not try to model itself.
        //
        //   Impersonator::approvalEligibilityUsing(
        //       fn (object $reviewer, ApprovalRequest $r): bool => …,
        //   );
        //
        // Fails closed: anything other than a literal true refuses, including a
        // thrown exception, matching how authorization.roles.hierarchy behaves.
        'eligibility' => null,

        // Modes exempt from approval. Read-only support work usually should not
        // need a second operator; `full` access usually should. This is the point
        // of the feature, not a loophole: requiring a second person for routine
        // read-only work trains everyone to approve reflexively, which is how a
        // four-eyes control degrades into a rubber stamp.
        'except_modes' => [Mode::READ_ONLY],

        // Days to keep *decided* requests. Open requests are never pruned however
        // old they look — deleting the record that somebody asked for access to an
        // account is exactly what an auditor came to read. Null keeps everything.
        'retention_days' => env('IMPERSONATOR_APPROVAL_RETENTION_DAYS'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Doctor
    |--------------------------------------------------------------------------
    | Settings for `php artisan laranail::impersonator.doctor`.
    */

    'doctor' => [
        // Provider class => package name. The doctor warns when any of these is
        // installed alongside this package: both register routes and session
        // state, and leaving through one does not end an impersonation started
        // by the other — which produces an audit trail that disagrees with
        // itself. Add your own; nothing here is a hard conflict.
        'conflicting_packages' => [
            'Lab404\Impersonate\ImpersonateServiceProvider' => 'lab404/laravel-impersonate',
            'Octopy\Impersonate\ImpersonateServiceProvider' => 'octopyid/laravel-impersonate',
            'Stechstudio\FilamentImpersonate\FilamentImpersonateServiceProvider' => 'stechstudio/filament-impersonate',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    | Every lifecycle event — entered, left, expired, revoked, rejected — with
    | structured context. Rejections log their decision code. Raw token and
    | credential values never appear.
    */

    /*
    |--------------------------------------------------------------------------
    | PostgreSQL row-level security
    |--------------------------------------------------------------------------
    | RLS matters more here than in most packages. If your application scopes
    | rows by a session GUC that still names the **operator**, an impersonated
    | session sees the operator's rows while claiming to be the customer — the
    | exact inversion impersonation exists to avoid.
    |
    | **The main fix is not this config.** It is reading
    | `RlsContext::effective()` in your own scoping layer instead of
    | `auth()->id()`, which is a one-line change. See docs/recipes.
    |
    | What this switch adds is defence in depth: the middleware publishes the
    | impersonation context as transaction-scoped GUCs, so a policy can refuse
    | writes under `read_only` at the database level, independently of the PHP
    | guard.
    |
    | Set transaction-scoped on purpose. A session-scoped GUC leaks to the next
    | client that receives the connection under PgBouncer in transaction mode,
    | which is a data breach and the most-cited RLS footgun there is.
    */

    'rls' => [
        'enabled' => env('IMPERSONATOR_RLS_ENABLED', false),

        // Null uses the default connection. Ignored on any driver but pgsql.
        'connection' => env('IMPERSONATOR_RLS_CONNECTION'),

        // GUC namespace: app.impersonated_user_id, app.impersonator_id, and so on.
        'prefix' => env('IMPERSONATOR_RLS_PREFIX', 'app'),
    ],

    'logging' => [
        'enabled' => true,

        // Null uses the default channel.
        'channel' => env('IMPERSONATOR_LOG_CHANNEL'),

        'level' => env('IMPERSONATOR_LOG_LEVEL', 'info'),

        // Refusals are the security-relevant half of the signal.
        'rejection_level' => env('IMPERSONATOR_LOG_REJECTION_LEVEL', 'warning'),

        // A **second** channel for the tamper-relevant subset: started, ended,
        // extended, revoked, expired, mode violations and every approval
        // decision. Written in addition to the channel above, never instead of
        // it — an operator reading application logs during an incident should not
        // have to know the interesting lines went elsewhere.
        //
        // Why bother: ASVS 16.4.2/16.4.3 require that logs cannot be modified and
        // are shipped off-box, and an audit table writable by the application's
        // own database user does not meet that. The HMAC chain gives tamper
        // *evidence*, not tamper *resistance* — only an external sink closes the
        // gap. Point this at a syslog, a SIEM, or anything append-only.
        //
        // A channel name that does not resolve is ignored rather than fatal: the
        // ordinary line is already written by then, so a typo costs a copy rather
        // than a record.
        'audit_channel' => env('IMPERSONATOR_AUDIT_LOG_CHANNEL'),
    ],

];
