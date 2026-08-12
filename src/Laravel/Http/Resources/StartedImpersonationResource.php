<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;

/**
 * The response to starting an impersonation — the **only** place a secret is ever emitted.
 *
 * Two shapes, matching the two outcomes, and keeping them distinct matters: a `pending` handoff has
 * not impersonated anybody, so a client that treated it as live would show "now impersonating" for
 * a session that was never created.
 *
 *  - **pending** — carries `accept_url`, whose token is a live single-use credential.
 *  - **started** — carries `credential`, whose `secret` is readable exactly once and is never
 *    retrievable again. Only its SHA-256 digest was stored.
 *
 * Every *other* endpoint returns `ImpersonationResource`, which cannot emit either.
 *
 * @property-read ImpersonationOutcome $resource
 */
class StartedImpersonationResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $credential = $this->resource->credential;

        return array_filter([
            'pending' => $this->resource->pending,
            'impersonation' => $this->resource->session->toArray(),
            'redirect_to' => $this->resource->redirectTo,

            // Present only for a handoff. The token inside is short-lived and single-use, but until
            // it is redeemed anyone holding this URL can enter the account — so a client must treat
            // the whole response as a secret and must not log it.
            'accept_url' => $this->resource->pending ? $this->resource->acceptUrl() : null,

            'credential' => $credential === null || ! $credential->hasSecret() ? null : [
                'type' => $credential->type->value,
                // Shown once. Not stored, not recoverable, not present on any other endpoint.
                'secret' => $credential->secret(),
                'expires_at' => $credential->expiresAt?->format(DATE_ATOM),
                // Deliberately included so a client knows what the credential may do without
                // having to decode it.
                'metadata' => $credential->metadata,
            ],
        ], static fn (mixed $value): bool => $value !== null);
    }
}
