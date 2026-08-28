<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Services;

use Throwable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Auth\Authenticatable;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ExtensionGrant;
use Simtabi\Laranail\Impersonator\Core\Values\ExtensionPolicy;
use Simtabi\Laranail\Impersonator\Core\Values\ExtensionOutcome;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Actions\EnterImpersonation;
use Simtabi\Laranail\Impersonator\Laravel\Actions\LeaveImpersonation;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Laravel\Actions\ExtendImpersonation;
use Simtabi\Laranail\Impersonator\Laravel\Actions\RevokeImpersonation;

/**
 * The lifecycle orchestration layer, composing the actions.
 *
 * The split between this and the manager is deliberate. `ImpersonationManager` is the
 * composition root — it resolves drivers, adapters and modes and owns the extension
 * points. This service is the *behaviour*: it turns application-level arguments into a
 * request, picks the driver, and delegates to a single-purpose action.
 *
 * Keeping them apart means the manager can be asked "which driver would you use" in a
 * doctor command without any risk of performing an impersonation, and this service can
 * be tested against a fake driver without a container.
 *
 * Everything is constructor-injected. Nothing here reaches into the container at call
 * time, so a host application can replace any single collaborator through a binding.
 */
final readonly class ImpersonationService
{
    public function __construct(
        private ImpersonationManager $manager,
        private EnterImpersonation $enter,
        private LeaveImpersonation $leave,
        private RevokeImpersonation $revoke,
        private ExtendImpersonation $extend,
    ) {}

    /**
     * @param array<string, mixed> $metadata
     *
     * @throws ImpersonationDenied
     */
    public function enter(
        Authenticatable|Model $target,
        string|Mode|null $mode = null,
        ?string $reason = null,
        ?string $redirectTo = null,
        Authenticatable|Model|null $impersonator = null,
        ?string $driver = null,
        ?string $adapter = null,
        array $metadata = [],
    ): ImpersonationOutcome {
        $request = $this->manager->buildRequest(
            target: $target,
            mode: $mode,
            reason: $reason,
            redirectTo: $redirectTo,
            impersonator: $impersonator,
            driver: $driver,
            adapter: $adapter,
            metadata: $metadata,
        );

        return $this->enterRequest($request);
    }

    /** Enter from an already-assembled request — the path a Form Request takes. */
    public function enterRequest(ImpersonationRequest $request): ImpersonationOutcome
    {
        return ($this->enter)($request, $this->manager->driver($request->driver));
    }

    /** Complete a cross-domain handoff by redeeming its single-use token. */
    public function complete(string $token, ?string $driver = null): ImpersonationOutcome
    {
        return $this->manager->driver($driver)->complete($token);
    }

    public function leave(EndReason $reason = EndReason::Left, ?string $driver = null): ?ImpersonationSession
    {
        $session = $this->manager->current();

        if ($session === null) {
            return null;
        }

        return ($this->leave)($session, $this->manager->driver($driver ?? $session->driver), $reason);
    }

    /**
     * Buy more time on the impersonation running in this context.
     *
     * Named for what it extends rather than just `extend()`, because the manager it is
     * reached through already has an `extend()` — Laravel's driver-registration method — and
     * two methods a character apart doing entirely different things is a trap.
     *
     * Returns a refusal rather than throwing when there is nothing to extend. Asking for more
     * time is a question, and the caller rendering a button needs the reason to display.
     */
    public function extendSession(?ExtensionPolicy $policy = null): ExtensionOutcome
    {
        $session = $this->manager->current();

        if ($session === null) {
            return new ExtensionOutcome(null, ExtensionGrant::refuse(Decision::deny(
                Decision::NOT_IMPERSONATING,
                'There is no active impersonation to extend.',
            )));
        }

        return ($this->extend)($session, $policy ?? $this->manager->extensionPolicy());
    }

    /**
     * End an impersonation the caller does not own.
     *
     * The adapter is resolved from the row's own adapter name, not from current
     * config: a revocation may well arrive after config changed, and the credential
     * that needs invalidating is the one that was actually issued.
     */
    public function revoke(string $auditId, ?Identity $revokedBy = null, ?string $note = null): ImpersonationSession
    {
        $session = $this->manager->auditStore()->find($auditId);

        $adapter = null;

        if ($session !== null && $this->manager->hasAdapter($session->adapter)) {
            try {
                $adapter = $this->manager->adapter($session->adapter);
            } catch (Throwable) {
                // An adapter whose package has since been removed cannot revoke a
                // credential, but the row must still be marked. Degrading here is
                // what keeps the kill switch working through a dependency change.
                $adapter = null;
            }
        }

        return ($this->revoke)($auditId, $revokedBy, $note, $adapter);
    }
}
