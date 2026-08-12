<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Simtabi\Laranail\Impersonator\Core\Values\ApprovalRequest;

/**
 * One break-glass request, as the API represents it.
 *
 * @property-read ApprovalRequest $resource
 */
class ApprovalResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        // The value object's own projection, for the same reason as ImpersonationResource: it omits
        // the fingerprint and the stored request payload by construction. Assembling this by hand
        // would eventually leak the fingerprint — which is a verifier, and an approval queue is a
        // screen that operators holding `approve` but not `enter` can see.
        return $this->resource->toArray();
    }
}
