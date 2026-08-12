<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Exceptions;

final class NotImpersonating extends ImpersonationException
{
    public static function make(): self
    {
        return new self('There is no active impersonation to act on.');
    }
}
