<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Requests\Api;

use Illuminate\Validation\Rule;
use Illuminate\Foundation\Http\FormRequest;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;
use Simtabi\Laranail\Impersonator\Core\Support\ModeRegistry;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;

/**
 * Validation for the audit listing.
 *
 * Reading the trail is its own permission, checked here rather than in the controller: the audit
 * list is the one endpoint where an unauthorised caller learns something merely by the shape of
 * the response, so it is refused before any query runs.
 *
 * Filters are constrained to known values — modes against the registry, end reasons against the
 * enum — so an unrecognised filter is a 422 rather than a silently empty page that reads as
 * "no impersonations happened".
 */
class ListAuditsRequest extends FormRequest
{
    public function authorize(): bool
    {
        $operator = app(ImpersonationManager::class)->currentImpersonatorOrNull();

        if ($operator === null) {
            return false;
        }

        return app(AuthorizationPolicy::class)
            ->authorizeAuditAccess(app(ImpersonationManager::class)->identities()->fromUser($operator))
            ->allowed;
    }

    /** @return array<string, array<int, mixed>> */
    public function rules(): array
    {
        $settings = app(Settings::class);

        return [
            'impersonator' => ['sometimes', 'string', 'max:255'],
            'target'       => ['sometimes', 'string', 'max:255'],
            'tenant'       => ['sometimes', 'string', 'max:255'],
            'mode'         => ['sometimes', 'string', Rule::in(app(ModeRegistry::class)->names())],
            'driver'       => ['sometimes', 'string', 'max:64'],
            'ended_by'     => ['sometimes', 'string', Rule::in(array_column(EndReason::cases(), 'value'))],
            'active'       => ['sometimes', 'boolean'],
            'from'         => ['sometimes', 'date'],
            'to'           => ['sometimes', 'date', 'after_or_equal:from'],
            'per_page'     => ['sometimes', 'integer', 'min:1', 'max:' . $settings->int('api.max_per_page', 100)],
        ];
    }

    /** @return array<string, string> */
    public function messages(): array
    {
        return [
            'mode.in'     => 'That impersonation mode is not registered.',
            'ended_by.in' => 'That is not a recognised end reason.',
        ];
    }
}
