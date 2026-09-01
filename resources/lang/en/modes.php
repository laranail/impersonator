<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Mode display names
|--------------------------------------------------------------------------
| The banner and badge previously rendered a mode by running
| `str_replace('_', ' ', $mode)` over its raw config key, which produces
| "read only" — a value, not a label, and untranslatable by construction.
|
| A mode is user-registrable, so an unknown one falls back to that same
| humanised form rather than rendering blank.
*/

return [
    'full' => [
        'name' => 'Full access',
        'short' => 'Full',
    ],
    'read_only' => [
        'name' => 'Read only',
        'short' => 'Read only',
    ],
    'limited' => [
        'name' => 'Limited',
        'short' => 'Limited',
    ],
];
