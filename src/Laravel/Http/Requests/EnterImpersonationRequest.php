<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Requests;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\In;
use Simtabi\Laranail\Impersonator\Core\Support\ModeRegistry;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\RedirectGuard;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * Validation for the enter endpoint. No inline validation anywhere in the package.
 *
 * Every rule here closes a specific injection route, which is why they are `in`
 * constraints against runtime registries rather than string checks:
 *
 *  - **`target_type` must be an allowlisted morph alias.** Without it, a caller names
 *    any Eloquent class and has the package load it.
 *  - **`mode` must be registered.** An unregistered mode would otherwise reach the
 *    registry and throw a 500 where a 422 belongs — and a *misspelled* one must never
 *    silently widen the envelope.
 *  - **`guard` must exist in `config('auth.guards')`.** A bogus guard name would
 *    authenticate against the wrong provider.
 *  - **`redirect_to` must survive the redirect guard.** An open redirect on an
 *    impersonation endpoint is a credential-phishing primitive.
 *
 * Authorization is *not* done here. `authorize()` only confirms somebody is signed in;
 * the impersonation decision belongs to the single AuthorizationPolicy that every
 * entry point shares, so that a Form Request cannot become a second, divergent copy
 * of those rules.
 */
class EnterImpersonationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->impersonator()->currentImpersonatorOrNull() !== null;
    }

    /** @return array<string, list<ValidationRule|In|string>> */
    public function rules(): array
    {
        $settings = app(Settings::class);

        return [
            'target_type' => [
                'required',
                'string',
                Rule::in(array_keys($this->impersonator()->identities()->allowlist())),
            ],
            'target_id' => ['required', 'string', 'max:255'],
            'mode' => ['sometimes', 'nullable', 'string', Rule::in(app(ModeRegistry::class)->names())],
            'guard' => ['sometimes', 'nullable', 'string', Rule::in(array_keys($this->configuredGuards()))],
            'reason' => [
                $settings->bool('reason.require', false) ? 'required' : 'nullable',
                'string',
                'min:' . $settings->int('reason.min_length', 3),
                'max:' . $settings->int('reason.max_length', 500),
            ],
            'redirect_to' => ['sometimes', 'nullable', 'string', 'max:2048', $this->safeRedirect()],
        ];
    }

    /** @return array<string, string> */
    public function messages(): array
    {
        return [
            'target_type.in' => __('laranail-impersonator::validation.target_type.in'),
            'mode.in' => __('laranail-impersonator::validation.mode.in'),
            'guard.in' => __('laranail-impersonator::validation.guard.in'),
        ];
    }

    /** Assemble the domain request, so the controller stays a handful of lines. */
    public function toImpersonationRequest(): ImpersonationRequest
    {
        $manager = $this->impersonator();
        $identities = $manager->identities();

        $target = $identities->toUser($identities->identity(
            (string) $this->string('target_type'),
            (string) $this->string('target_id'),
        ));

        // Should be unreachable: the allowlist rule passed, so the type resolves. A
        // missing row is a 404 rather than an authorization failure.
        abort_if($target === null, 404, 'That account could not be found.');

        return $manager->buildRequest(
            target: $target,
            mode: $this->optionalString('mode'),
            reason: $this->optionalString('reason'),
            redirectTo: $this->optionalString('redirect_to'),
            metadata: ['entered_via' => 'http'],
        );
    }

    /**
     * A closure rule rather than a regex: the redirect guard is the single
     * implementation, and a second spelling of "is this URL safe" in a validation rule
     * is a second thing to get wrong.
     */
    private function safeRedirect(): ValidationRule
    {
        return new class implements ValidationRule
        {
            public function validate(string $attribute, mixed $value, \Closure $fail): void
            {
                if (is_string($value) && $value !== '' && ! app(RedirectGuard::class)->isSafe($value)) {
                    $fail('The redirect target is not permitted.');
                }
            }
        };
    }

    /** Validated input as a string, or null when absent or blank. */
    private function optionalString(string $key): ?string
    {
        $value = $this->input($key);

        return is_string($value) && trim($value) !== '' ? $value : null;
    }

    /** @return array<array-key, mixed> */
    private function configuredGuards(): array
    {
        $guards = config('auth.guards', []);

        return is_array($guards) ? $guards : [];
    }

    private function impersonator(): ImpersonationManager
    {
        return app(ImpersonationManager::class);
    }
}
