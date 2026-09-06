<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Blade component labels
|--------------------------------------------------------------------------
| Here rather than as promoted-property defaults, because a promoted default
| must be a constant expression — `public string $label = __('…')` is a parse
| error. The properties are nullable and resolve these at render time, so an
| application can still pass `label="…"` and override them.
*/

return [
    'impersonate' => 'Impersonate',
    'leave'       => 'Stop impersonating',
];
