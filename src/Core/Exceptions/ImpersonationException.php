<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Exceptions;

use RuntimeException;

/**
 * Base for every failure the package raises. Catch this to handle any
 * impersonation problem without coupling to the specific subclass.
 */
class ImpersonationException extends RuntimeException {}
