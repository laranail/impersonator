<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Exceptions;

use InvalidArgumentException;

final class InvalidMode extends InvalidArgumentException
{
    public static function malformed(string $name): self
    {
        return new self(sprintf(
            'Impersonation mode [%s] is malformed; use lower snake_case, e.g. "read_only".',
            $name,
        ));
    }

    /** @param list<string> $registered */
    public static function unregistered(string $name, array $registered): self
    {
        return new self(sprintf(
            'Impersonation mode [%s] is not registered. Available modes: %s.',
            $name,
            $registered === [] ? '(none)' : implode(', ', $registered),
        ));
    }
}
