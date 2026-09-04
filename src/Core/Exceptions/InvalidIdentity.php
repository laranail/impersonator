<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Exceptions;

use InvalidArgumentException;

final class InvalidIdentity extends InvalidArgumentException
{
    public static function emptyType(): self
    {
        return new self('An identity type cannot be empty.');
    }

    public static function emptyId(): self
    {
        return new self('An identity id cannot be empty.');
    }

    public static function unusableKey(string $class, string $givenType): self
    {
        return new self(sprintf(
            'Cannot build an identity for [%s]: its key is %s, but an audit row can only '
            . 'store and later resolve an int or a string. Is the model unsaved?',
            $class,
            $givenType,
        ));
    }
}
