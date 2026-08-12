<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Validation messages
|--------------------------------------------------------------------------
| Overrides for the rules the package's Form Requests declare. Deliberately
| vague about *why* a target type was rejected: the allowlist is a security
| control, and enumerating what is impersonatable helps somebody probing it.
*/

return [
    'target_type' => [
        'in' => 'That type of account cannot be impersonated.',
    ],
    'mode' => [
        'in' => 'That impersonation mode is not available.',
    ],
    'guard' => [
        'in' => 'That authentication guard does not exist.',
    ],
];
