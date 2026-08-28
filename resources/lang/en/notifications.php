<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Notifications
|--------------------------------------------------------------------------
| Two audiences with opposite needs, so they read very differently.
|
| `target` goes to the **customer** whose account was entered. It never names
| the operator: telling a customer which employee opened their account invites
| them to contact that person directly, and the audit trail is the correct
| place for that fact. It reads as reassurance, not as an alert.
|
| `security` and `approval` go to **staff**. They name specifics because the
| reader is expected to act on them.
|
| Dates are formatted through `:date`, filled by the caller with a localised
| value. The previous English literal escaped the word "at" *into* the format
| string (`'j F Y \a\t H:i T'`), so a French locale rendered a French month
| beside an English preposition — a defect no lang file alone could fix.
*/

return [

    'target' => [
        // Used when `app.name` is unset. Deliberately vague and first-person-plural: the customer is
        // being told their account was opened, and a blank or a placeholder there reads as a phishing
        // attempt at exactly the moment they are deciding whether to trust the mail.
        'fallback_app_name' => 'Our team',

        'subject'  => ':app accessed your account',
        'accessed' => 'A member of our support team accessed your account on :date.',
        'routine'  => 'This is a routine part of helping with a support request. If you were not expecting it, please reply to this message.',

        'mode' => [
            'read_only' => 'They could view your account but could not change anything.',
            'limited'   => 'They could help with your account, but could not change your password, security settings or billing details.',
            'default'   => 'They had the same access to your account that you do.',
        ],
    ],

    /*
     * Label-value lines shared by the staff notifications. One group, so "Operator" cannot read
     * differently in the security alert than in the approval request.
     */
    'fields' => [
        'operator'   => 'Operator: :value',
        'target'     => 'Target: :value',
        'mode'       => 'Mode: :value',
        'reason'     => 'Reason: :value',
        'audit_id'   => 'Audit id: :value',
        'request_id' => 'Request id: :value',
        'expires'    => 'Expires: :value',
        'note'       => 'Note from the approver: :value',
        'none_given' => 'none given',
    ],

    'security' => [
        'subject' => '[:app] Impersonation alert: :summary',

        'summary' => [
            'revoked'         => 'An impersonation was revoked by an administrator.',
            'full_mode_enter' => 'An operator entered an account with full access.',
            'expired'         => 'An impersonation was force-ended after reaching its time limit.',
            'default'         => 'An impersonation event occurred.',
        ],
    ],

    'approval' => [
        'requested' => [
            'subject' => '[:app] Impersonation approval requested',
            'line'    => 'An operator is asking for approval to impersonate an account.',
            'action'  => 'Approve or deny it from your administration area. You cannot approve your own request.',
        ],

        // Three complete sentences, never an adjective spliced into a template. Word order is not
        // universal, so "Your request was :outcome" cannot be translated correctly for every locale.
        'decided' => [
            'approved'         => 'Your impersonation request was approved.',
            'denied'           => 'Your impersonation request was denied.',
            'expired'          => 'Your impersonation request expired before anyone decided it.',
            'subject_approved' => '[:app] Impersonation request approved',
            'subject_denied'   => '[:app] Impersonation request denied',
            'subject_expired'  => '[:app] Impersonation request expired',

            // The window is the one on the *approval*, not a fresh one. An operator who thinks they
            // have fifteen minutes from reading the mail will find the permit already dead.
            'window' => 'You may now start the impersonation once, until :date.',
        ],
    ],
];
