<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Requests\Api;

use Illuminate\Foundation\Http\FormRequest;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuthorizationPolicy;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * Validation for the approver's queue.
 *
 * The queue is gated on the approve permission rather than the audit permission. They answer
 * different questions — "may you decide these" versus "may you read what happened" — and an auditor
 * who can read every impersonation has no reason to see live requests awaiting a decision.
 *
 * A caller's *own* requests are a separate endpoint with no permission at all, since an operator can
 * always see what they themselves asked for.
 */
class ListApprovalsRequest extends FormRequest
{
    public function authorize(): bool
    {
        $manager = app(ImpersonationManager::class);
        $operator = $manager->currentImpersonatorOrNull();

        if ($operator === null) {
            return false;
        }

        return app(AuthorizationPolicy::class)
            ->authorizeApproval($manager->identities()->fromUser($operator))
            ->allowed;
    }

    /** @return array<string, array<int, mixed>> */
    public function rules(): array
    {
        $max = app(Settings::class)->int('api.max_per_page', 100);

        return [
            'per_page' => ['sometimes', 'integer', 'min:1', 'max:'.$max],
            'offset' => ['sometimes', 'integer', 'min:0'],
        ];
    }

    public function perPage(): int
    {
        $settings = app(Settings::class);
        $requested = $this->input('per_page');

        if (! is_numeric($requested)) {
            return min($settings->int('api.per_page', 25), $settings->int('api.max_per_page', 100));
        }

        return min((int) $requested, $settings->int('api.max_per_page', 100));
    }

    public function offset(): int
    {
        $offset = $this->input('offset');

        return is_numeric($offset) ? max(0, (int) $offset) : 0;
    }
}
