<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Laravel\Actions\EnterImpersonation;
use Simtabi\Laranail\Impersonator\Laravel\Actions\LeaveImpersonation;
use Simtabi\Laranail\Impersonator\Laravel\Actions\RevokeImpersonation;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

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
            } catch (\Throwable) {
                // An adapter whose package has since been removed cannot revoke a
                // credential, but the row must still be marked. Degrading here is
                // what keeps the kill switch working through a dependency change.
                $adapter = null;
            }
        }

        return ($this->revoke)($auditId, $revokedBy, $note, $adapter);
    }
}
