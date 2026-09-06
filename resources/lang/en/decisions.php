<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Refusal messages
|--------------------------------------------------------------------------
| One entry per `Decision` code. These are **display** text: the code beside
| them is the stable contract and never moves, which is what the REST API
| returns as `reason` and what a client should branch on.
|
| Resolved by MessageCatalog, which cascades specific -> general -> the
| English literal built in Core. Two consequences worth knowing:
|
|  - **Deleting a key is safe.** The literal is used instead, so a partly
|    translated file degrades to English rather than to a blank or a raw key.
|  - **A code is not a unique message.** Several sentences share one code, so
|    those codes nest under a `detail` sub-key matching the `detail` context
|    entry the refusing call site sets. The bare key is the fallback for any
|    detail that has no line of its own.
|
| `:placeholders` are filled from the decision's own `context`, so only the
| scalar entries a site actually passes are available.
*/

return [

    // ── Identity rules ──────────────────────────────────────────────────
    'self_impersonation'   => 'You cannot impersonate yourself.',
    'nested_impersonation' => 'You are already impersonating. Leave the current impersonation first.',
    'target_soft_deleted'  => 'That account has been deleted and cannot be impersonated.',
    'target_opted_out'     => 'That account cannot be impersonated.',

    'target_not_allowlisted' => [
        'type'    => 'That target type cannot be impersonated.',
        'missing' => 'The impersonation target could not be found.',
    ],

    // ── Permissions ─────────────────────────────────────────────────────
    'impersonator_not_permitted' => [
        'unauthenticated' => 'There is no authenticated user to check a mode against.',
        'unresolved'      => 'The impersonator could not be resolved.',
        'default'         => 'You are not permitted to impersonate.',
    ],

    'missing_permission'      => 'You are not permitted to impersonate.',
    'missing_mode_permission' => 'Impersonation mode [:mode] is not registered.',
    'protected_role'          => 'That account holds a protected role and cannot be impersonated.',

    'hierarchy_violation' => [
        'level' => 'You cannot impersonate an account at or above your own level.',
        // A misconfiguration rather than a refusal the operator can act on. Kept distinct because
        // telling somebody they lack permission when the rule itself is broken sends them asking
        // for access they already have.
        'not_callable' => 'The configured impersonation hierarchy rule is not callable.',
        'rule'         => 'The impersonation hierarchy rule refused this impersonation.',
        'default'      => 'You cannot impersonate that account.',
    ],

    'gate_denied' => [
        'unresolved' => 'The impersonation participants could not be resolved for the gate check.',
        'default'    => 'You are not authorized to impersonate that account.',
    ],

    // ── Preconditions ───────────────────────────────────────────────────
    'disabled'        => 'Impersonation is disabled for this application.',
    'reason_required' => [
        'missing' => 'A reason is required to impersonate.',
        'length'  => 'The reason must be between :min and :max characters.',
    ],

    // Pluralised, not `impersonation(s)`. `trans_choice` picks the form, which is the only way this
    // reads correctly in a language whose plural rules are not English's.
    'concurrency_limit' => 'You already have :active active impersonation, which is the limit.'
        . '|You already have :active active impersonations, which is the limit.',

    'approver_not_eligible' => [
        'role'    => 'You do not hold a role this request is still waiting on.',
        'rule'    => 'You are not eligible to decide this request.',
        'default' => 'You are not eligible to decide this request.',
    ],

    'step_up_required'    => 'Confirm your password before impersonating.',
    'target_not_eligible' => 'That account cannot be impersonated right now.',
    'session_idle'        => 'This impersonation ended after a period of inactivity.',

    'target_busy'       => 'Somebody else is already impersonating that account.',
    'approval_required' => 'This impersonation needs approval from a second operator.',
    'rate_limited'      => 'Too many impersonation attempts. Try again shortly.',

    // ── While impersonating ─────────────────────────────────────────────
    'mode_forbids_write' => [
        'read_only_persistence' => 'This impersonation is read-only, so nothing can be changed.',
        'read_only'             => 'This impersonation is read-only, so that action is not permitted.',
        'default'               => 'That operation is not permitted while impersonating.',
    ],

    'session_terminated' => [
        'ended'   => 'This impersonation has already ended.',
        'revoked' => 'This impersonation was ended by an administrator.',
        'expired' => 'This impersonation has expired. Enter again to continue.',
        'default' => 'This impersonation is no longer active.',
    ],

    'not_impersonating' => 'There is no active impersonation to extend.',

    // ── Extension ───────────────────────────────────────────────────────
    'extension_disabled'  => 'This impersonation cannot be extended.',
    'extension_limit'     => 'This impersonation has already been extended as many times as allowed.',
    'extension_too_early' => 'There is still time left on this impersonation. Extend it closer to the end.',

    'extension_ceiling' => [
        'unlimited' => 'This impersonation has no time limit, so there is nothing to extend.',
        'default'   => 'This impersonation has reached the longest it may run. Leave and enter again if you need more time.',
    ],
];
