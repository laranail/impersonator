<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Validation for the accept route.
 *
 * `authorize()` returns true, and that is correct rather than an oversight: the caller is
 * by definition *not* authenticated here — the whole point of a handoff is that they are
 * arriving on a host their session does not reach. The token is the credential, and the
 * driver verifies it and then re-runs the full authorization stack.
 *
 * The route parameter is bounded so a multi-megabyte path segment is rejected before any
 * hashing or database work happens. The length is generous: the token is base64url of at
 * least 32 bytes, and an application may have raised `tokens.bytes`.
 */
class AcceptImpersonationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, array<int, string>> */
    public function rules(): array
    {
        return [
            'token' => ['required', 'string', 'min:32', 'max:512'],
        ];
    }

    /** @return array<string, mixed> */
    public function validationData(): array
    {
        // The token arrives as a route parameter, not as input.
        return ['token' => $this->route('token')];
    }
}
