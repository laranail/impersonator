<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Exception messages
|--------------------------------------------------------------------------
| Keyed on the code each exception reports — `code()` or `reason()` — and
| resolved by MessageCatalog with the exception's own message as the fallback.
|
| Same contract as decisions.php: the code is stable and the message is not.
*/

return [

    // A refusal that reached the caller as an exception rather than a Decision. The specific rule is
    // in decisions.php; this is only the generic case.
    'impersonation_denied' => 'That impersonation is not permitted.',

    'approval_required' => 'This impersonation needs approval from a second operator.',
    'concurrency_limit' => 'You already have as many active impersonations as allowed.',
    'not_impersonating' => 'There is no active impersonation.',
    'audit_row_missing' => 'That impersonation record could not be found.',

    /*
     * **One line for every token failure, deliberately.**
     *
     * TokenRejected has four factories — unknown, expired, already_used, revoked — and they all
     * produce this one sentence. Four lines here would rebuild the oracle the Core class exists to
     * avoid: telling somebody probing the accept route that a token merely *expired* tells them the
     * token was real, and that a guessed one was close.
     *
     * The distinguishing reason still reaches the audit log through `reason()`. It must never reach
     * the client, so there is deliberately no `token_rejected.expired` key to add.
     */
    'token_rejected' => 'This impersonation link is no longer valid.',

    /*
     * The opposite case: these four are safe to distinguish.
     *
     * An approver is authenticated, is looking at a request they were shown, and needs to know why it
     * cannot be decided. Nothing is leaked by saying somebody else answered first.
     */
    'approval_not_decidable' => [
        'unknown'         => 'That approval request no longer exists.',
        'already_decided' => 'That request has already been answered.',
        'expired'         => 'That request expired before it was answered.',
        'self_approval'   => 'You cannot approve your own request.',
    ],
];
