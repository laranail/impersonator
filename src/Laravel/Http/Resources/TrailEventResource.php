<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Simtabi\Laranail\Impersonator\Core\Values\TrailEvent;

/**
 * One recorded action from an impersonation's trail.
 *
 * @property-read TrailEvent $resource
 */
class TrailEventResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return $this->resource->toArray();
    }
}
