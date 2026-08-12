<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Requests\Api;

use Simtabi\Laranail\Impersonator\Laravel\Http\Requests\EnterImpersonationRequest;

/**
 * Validation for `POST /impersonations`.
 *
 * Deliberately the web Form Request unchanged. The API and the HTML endpoint accept the same body,
 * enforce the same target allowlist, the same mode registry, the same guard check and the same
 * redirect guard — and two copies of those rules would eventually disagree, with the API being the
 * one nobody notices has drifted.
 */
class StartImpersonationRequest extends EnterImpersonationRequest {}
