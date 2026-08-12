<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Commands\Concerns;

use Illuminate\Console\Parser;
use ReflectionProperty;
use Symfony\Component\Console\Command\Command as SymfonyCommand;
use Symfony\Component\Console\Input\InputDefinition;

/**
 * Lets a command be named `laranail::impersonator.thing`.
 *
 * Symfony's `Command::validateName()` enforces `^[^:]++(:[^:]++)*$`, which rejects the empty
 * segment in `::`. The name is therefore written *past* that validator after construction,
 * which is safe because dispatch still works: Symfony resolves an exact name match before it
 * tries splitting on `:`.
 *
 * The signature is returned from `namespacedSignature()` rather than set on Laravel's
 * `$signature`, and that indirection is the whole trick: leaving `$signature` unset means
 * Laravel's constructor takes its `else` branch and hands Symfony a null name, which skips
 * validation entirely. Nothing has to be nulled, unset or reflected away first. The real name
 * is then parsed and written directly, past the validator.
 *
 * Reimplemented here rather than pulled in from `laranail/console`, deliberately: that package
 * requires PHP ^8.4.1 and this one targets ^8.3, so depending on it for a few dozen lines
 * would raise the floor for every consumer. The org standard explicitly sanctions the copy.
 */
trait SupportsNamespacedNames
{
    /** @var list<string> optional short aliases, applied after construction */
    protected array $commandAliases = [];

    public function __construct()
    {
        parent::__construct();

        $signature = $this->namespacedSignature();

        if ($signature !== '') {
            $this->applyNamespacedSignature($signature);
        }

        if ($this->commandAliases !== []) {
            $this->setAliases($this->commandAliases);
        }
    }

    /**
     * An option as a string, or null.
     *
     * Console input is `array|bool|float|int|string|null`, and a repeated option arrives as an
     * array — so casting blindly turns `--reason=a --reason=b` into the string "Array".
     */
    protected function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_scalar($value) && (string) $value !== '' ? (string) $value : null;
    }

    protected function stringArgument(string $name): string
    {
        $value = $this->argument($name);

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * Parse the signature and set the name directly.
     *
     * `setName()` runs the validator, so the property is written through reflection — the only
     * way to hold a name Symfony's regex rejects while keeping everything else ordinary.
     */
    protected function applyNamespacedSignature(string $signature): void
    {
        [$name, $arguments, $options] = Parser::parse($signature);

        $property = new ReflectionProperty(SymfonyCommand::class, 'name');
        $property->setValue($this, $name);

        $definition = new InputDefinition;

        foreach ($arguments as $argument) {
            $definition->addArgument($argument);
        }

        foreach ($options as $option) {
            $definition->addOption($option);
        }

        $this->setDefinition($definition);
    }

    /**
     * The command's signature, in `laranail::<slug>.<command>` form.
     *
     * A method rather than a trait property: a trait cannot declare a property that the using
     * class also declares with a different default — PHP rejects the composition outright. So
     * the consumer overrides this, and Laravel's own `$signature` is left untouched.
     */
    protected function namespacedSignature(): string
    {
        return '';
    }
}
