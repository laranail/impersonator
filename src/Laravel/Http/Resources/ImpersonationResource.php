<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/**
 * One impersonation, as the API represents it.
 *
 * @property-read ImpersonationSession $resource
 */
class ImpersonationResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        // `toArray()` on the value object is already the safe projection: it omits the credential
        // hash and the session id by construction. Building the payload field-by-field here would
        // eventually add one of them back by hand, which is exactly the mistake this avoids.
        return $this->resource->toArray();
    }
}
