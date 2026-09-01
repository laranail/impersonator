<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/**
 * Validation for the kill switch.
 *
 * The revoke *permission* is checked by the AuthorizationPolicy inside the action, not
 * here, so that the HTTP endpoint and an API or console revocation cannot drift apart.
 * This class only establishes that a caller is authenticated and that the audit id is
 * well-formed.
 */
class RevokeImpersonationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return app(ImpersonationManager::class)->currentImpersonatorOrNull() !== null;
    }

    /** @return array<string, array<int, string>> */
    public function rules(): array
    {
        return [
            // ULID length, so a malformed id is a 422 rather than a database lookup.
            'audit' => ['sometimes', 'string', 'size:26'],
            'note' => ['sometimes', 'nullable', 'string', 'max:500'],
        ];
    }
}
