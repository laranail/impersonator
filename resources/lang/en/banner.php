<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| The impersonation banner
|--------------------------------------------------------------------------
| Shown on every page of an impersonated session. Deliberately short: it has
| to fit one line on a phone without pushing the application's own chrome
| around.
*/

return [
    'impersonating' => 'Impersonating :target',
    'as' => 'as :impersonator',
    'since' => 'since :time',
    'expires' => 'expires :time',
    'extend' => 'Extend',
    'cannot_extend' => 'cannot extend',
    'leave' => 'Leave',

    'extended' => 'Impersonation extended by :minutes minute.|Impersonation extended by :minutes minutes.',

    'ended' => [
        'left' => 'You have left the impersonation.',
        'revoked' => 'This impersonation was ended by an administrator.',
        'expired' => 'This impersonation has expired.',
        'session_lost' => 'The impersonated session was lost.',
    ],
];
