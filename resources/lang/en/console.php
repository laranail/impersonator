<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Console output
|--------------------------------------------------------------------------
| Kept in its own file so an application can localise the user-facing surface
| and leave the CLI in English, which is a reasonable choice: an operator
| reading a terminal is usually reading English tooling around it.
|
| **Diagnostic detail is deliberately NOT here.** The doctor's explanatory
| paragraphs name config keys and artisan commands inline
| (`impersonator.limits.max_duration`,
| `php artisan vendor:publish --tag=impersonator-migrations`), and a
| half-translated paragraph wrapped around untranslatable identifiers reads
| worse than the English it replaced. What is translated is the short labels
| and the counted summaries — the lines whose *shape* is language-dependent.
|
| Every count below is a `trans_choice` line rather than a `row(s)` splice.
| Appending an `s` is only correct in a language that pluralises like English,
| and it is wrong even in English for an irregular noun.
*/

return [

    'doctor' => [
        'heading' => 'Impersonator diagnostics',
        'failed'  => ':failures check failed, :warnings. Impersonation is broken or a control is not enforcing.'
            . '|:failures checks failed, :warnings. Impersonation is broken or a control is not enforcing.',
        // A second, independently-counted noun in the same sentence, so it cannot ride on the same
        // `trans_choice` — that call pluralises on one number. Composed separately and spliced in
        // already-pluralised, which also lets a translator inflect it to match the clause around it.
        'warning_count' => ':count warning|:count warnings',
        'warnings'      => 'No failures, :count warning worth reading.|No failures, :count warnings worth reading.',
        'clean'         => 'Everything checks out.',
        'check_failed'  => 'The check itself failed to run: :message',
        'wrong_type'    => 'The container returned :type for this check rather than a :expected.',
    ],

    'prune_approvals' => [
        'expired' => ':count impersonation approval request expired.'
            . '|:count impersonation approval requests expired.',
    ],

    'prune_tokens' => [
        'pruned' => ':count impersonation handoff token pruned.'
            . '|:count impersonation handoff tokens pruned.',
    ],

    'verify_audit' => [
        'intact' => ':count audit row verified. The chain is intact.'
            . '|:count audit rows verified. The chain is intact.',
    ],

    'enter' => [
        'ambiguous' => 'Ambiguous :subject [:value]: :count target types are registered (:types). Qualify it as type:id.',
    ],

    'export_audit' => [
        'unknown_format' => 'Unknown format [:format]. Available: :formats.',
        'unwritable'     => 'Could not write the export to [:path].',
        'exported'       => 'Exported impersonation [:audit] to :path.',
    ],

    'scrub_identity' => [
        'malformed' => 'Give the identity as type:id, for example user:9902.',
        'no_rows'   => 'No audit rows mention that identity.',
        'dry_run'   => ':count audit row would have its labels nulled. Nothing was written.'
            . '|:count audit rows would have their labels nulled. Nothing was written.',
        'scrubbed' => ':count audit row scrubbed. The row and the hash chain are intact.'
            . '|:count audit rows scrubbed. The rows and the hash chain are intact.',
        // Reported even when zero, so an operator running this for an erasure request does not have to
        // wonder whether approvals were missed. Approvals store identities as morph pairs and never
        // denormalise a name, so there is nothing in them to scrub.
        'approvals' => ':count approval request mentions that identity; approvals hold no denormalised '
            . 'names, so none needed scrubbing.'
            . '|:count approval requests mention that identity; approvals hold no denormalised '
            . 'names, so none needed scrubbing.',
    ],
];
