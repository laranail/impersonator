<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Support;

use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Core\Contracts\ModeEnforcer;
use Simtabi\Laranail\Impersonator\Core\Exceptions\InvalidMode;

/**
 * The set of modes this installation recognises.
 *
 * Resolution is strict on purpose: an unknown mode raises InvalidMode rather
 * than falling back to a default. A typo in `default_mode` that silently
 * resolved to `full` would hand every operator unrestricted access, so the
 * failure has to be loud and at boot.
 */
final class ModeRegistry
{
    /** @var array<string, ModeEnforcer> */
    private array $enforcers = [];

    /** @param iterable<ModeEnforcer> $enforcers */
    public function __construct(iterable $enforcers = [])
    {
        foreach ($enforcers as $enforcer) {
            $this->register($enforcer);
        }
    }

    public function register(ModeEnforcer $enforcer): self
    {
        $this->enforcers[$enforcer->mode()] = $enforcer;

        return $this;
    }

    public function has(string $mode): bool
    {
        return isset($this->enforcers[$mode]);
    }

    /** @throws InvalidMode when the mode was never registered */
    public function enforcer(string|Mode $mode): ModeEnforcer
    {
        $name = $mode instanceof Mode ? $mode->name : $mode;

        return $this->enforcers[$name] ?? throw InvalidMode::unregistered($name, $this->names());
    }

    /** Validate a mode name and return it as a value object. */
    public function resolve(string $mode): Mode
    {
        if (! $this->has($mode)) {
            throw InvalidMode::unregistered($mode, $this->names());
        }

        return Mode::of($mode);
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_keys($this->enforcers);
    }

    /** @return array<string, ModeEnforcer> */
    public function all(): array
    {
        return $this->enforcers;
    }

    /**
     * Mode name to human description, for the banner, the API and the doctor
     * command.
     *
     * @return array<string, string>
     */
    public function descriptions(): array
    {
        return array_map(
            static fn (ModeEnforcer $enforcer): string => $enforcer->describe(),
            $this->enforcers,
        );
    }
}
