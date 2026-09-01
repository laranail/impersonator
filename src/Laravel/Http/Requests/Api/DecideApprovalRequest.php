<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Requests\Api;

use Illuminate\Foundation\Http\FormRequest;
use Simtabi\Laranail\Impersonator\Laravel\Actions\DecideApproval;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/**
 * Validation for granting or denying a break-glass request.
 *
 * The approve *permission*, and the rule that an approver is never the requester, are both checked
 * inside {@see DecideApproval} — so the API, a UI and a console decision cannot drift, and so the
 * four-eyes rule cannot be lost by adding a second entry point. This only establishes an
 * authenticated caller and a well-formed note.
 */
class DecideApprovalRequest extends FormRequest
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

    public function note(): ?string
    {
        $note = $this->input('note');

        return is_string($note) && $note !== '' ? $note : null;
    }
}
