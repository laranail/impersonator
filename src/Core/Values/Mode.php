<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use Stringable;
use Simtabi\Laranail\Impersonator\Core\Exceptions\InvalidMode;

/**
 * The privilege envelope an impersonation runs inside.
 *
 * This is a value object rather than an enum precisely because apps register
 * their own modes through the ModeEnforcer contract; a closed enum would make
 * the documented extension point impossible. The three built-ins are named
 * constants so the common case still reads like an enum at the call site.
 *
 * A Mode is chosen once, at enter time, and stored server-side. It is never
 * read back from client input on a later request — that is the whole mechanism
 * preventing mid-session escalation.
 */
final readonly class Mode implements Stringable
{
    public const string READ_ONLY = 'read_only';

    public const string LIMITED = 'limited';

    public const string FULL = 'full';

    public function __construct(public string $name)
    {
        if (! preg_match('/^[a-z][a-z0-9_]*$/', $name)) {
            throw InvalidMode::malformed($name);
        }
    }

    public function __toString(): string
    {
        return $this->name;
    }

    public static function readOnly(): self
    {
        return new self(self::READ_ONLY);
    }

    public static function limited(): self
    {
        return new self(self::LIMITED);
    }

    public static function full(): self
    {
        return new self(self::FULL);
    }

    public static function of(string $name): self
    {
        return new self($name);
    }

    /** @return list<string> */
    public static function builtIn(): array
    {
        return [self::READ_ONLY, self::LIMITED, self::FULL];
    }

    public function is(self|string $other): bool
    {
        return $this->name === ($other instanceof self ? $other->name : $other);
    }

    public function isNot(self|string $other): bool
    {
        return ! $this->is($other);
    }

    /**
     * The permission gating this mode, e.g. `impersonator.mode.read_only`.
     * Interpolated from a config template so apps can adopt their own
     * permission naming without a code change.
     */
    public function permission(string $template = 'impersonator.mode.%s'): string
    {
        return sprintf($template, $this->name);
    }
}
