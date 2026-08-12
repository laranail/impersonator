<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/**
 * Adds the impersonation API to a user model.
 *
 * Convenience only — every method here is reachable through the `Impersonator`
 * facade, and none of the authorization is implemented in this trait. That
 * matters: a model method that decided its own permissions could be bypassed by
 * calling the manager directly, so all of these delegate to the single
 * authorization stack instead.
 *
 * Override `canImpersonate()` and `canBeImpersonated()` to add model-level rules.
 * Both default to true, so adding the trait does not silently start refusing
 * things.
 */
trait Impersonates
{
    /**
     * Whether this user may impersonate at all.
     *
     * Consulted by the policy for the impersonator. Override to gate on your own
     * attributes, e.g. `return $this->is_staff && $this->email_verified_at !== null;`.
     */
    public function canImpersonate(): bool
    {
        return true;
    }

    /**
     * Whether this user may be impersonated by anyone.
     *
     * Consulted by the policy for the target — the model-level opt-out. Override
     * to protect specific accounts, e.g. `return ! $this->is_admin;`.
     */
    public function canBeImpersonated(): bool
    {
        return true;
    }

    /**
     * Begin impersonating another user.
     *
     * @param array<string, mixed> $metadata
     *
     * @throws ImpersonationDenied
     *                             when any rule in the authorization stack refuses
     */
    public function impersonate(
        Authenticatable|Model $target,
        string|Mode|null $mode = null,
        ?string $reason = null,
        ?string $redirectTo = null,
        array $metadata = [],
    ): ImpersonationOutcome {
        return $this->impersonator()->enter(
            target: $target,
            mode: $mode,
            reason: $reason,
            redirectTo: $redirectTo,
            // Passed explicitly rather than read from the guard: this call may
            // come from a queued job or a console command, where nobody is
            // authenticated but the impersonator is nonetheless known.
            impersonator: $this,
            metadata: $metadata,
        );
    }

    /** End the current impersonation. Always available, and only de-escalating. */
    public function leaveImpersonation(EndReason $reason = EndReason::Left): ?ImpersonationSession
    {
        return $this->impersonator()->leave($reason);
    }

    /**
     * Whether an impersonation is active in this request.
     *
     * A property of the request rather than of this model — asking a user object
     * whether "it" is impersonating is a question about the current session.
     */
    public function isImpersonating(): bool
    {
        return $this->impersonator()->isImpersonating();
    }

    /** Whether this user is the one currently being impersonated. */
    public function isBeingImpersonated(): bool
    {
        $session = $this->impersonator()->current();

        return $session !== null
            && $session->target->is($this->impersonator()->identities()->fromUser($this));
    }

    /**
     * The operator behind the current request: the impersonator while an
     * impersonation is active, and the authenticated user otherwise.
     *
     * Use this, not `auth()->user()`, whenever recording who did something.
     */
    public function impersonationActor(): Authenticatable|Model|null
    {
        return $this->impersonator()->actor();
    }

    /** The active mode, or null when not impersonating. */
    public function impersonationMode(): ?Mode
    {
        return $this->impersonator()->mode();
    }

    protected function impersonator(): ImpersonationManager
    {
        return app(ImpersonationManager::class);
    }
}
