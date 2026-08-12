<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Requests\Api;

use Illuminate\Foundation\Http\FormRequest;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/**
 * Validation for the API kill switch.
 *
 * The revoke *permission* is checked by the AuthorizationPolicy inside the action, so that the API,
 * the HTML endpoint and a console revocation cannot drift apart. This only establishes an
 * authenticated caller and a well-formed note.
 */
class RevokeImpersonationApiRequest extends FormRequest
{
    public function authorize(): bool
    {
        return app(ImpersonationManager::class)->currentImpersonatorOrNull() !== null;
    }

    /** @return array<string, array<int, string>> */
    public function rules(): array
    {
        return [
            'note' => ['sometimes', 'nullable', 'string', 'max:500'],
        ];
    }
}
