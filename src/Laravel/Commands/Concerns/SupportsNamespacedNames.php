<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Commands\Concerns;

use Illuminate\Console\Parser;
use Simtabi\Laranail\Console\Tools\Commands\Concerns\SupportsNamespacedNames as CanonicalNamespacedNames;
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
 * The reflection write itself is NOT reimplemented here. It comes from
 * `laranail/console`'s trait of the same name, which is the canonical one -- twenty-nine packages
 * in the family import it -- and this package already requires that dependency.
 *
 * It used to be a local copy, justified in this docblock by console requiring PHP ^8.4.1 while this
 * package targeted ^8.3. Both halves of that have since stopped being true: the floor here is
 * ^8.4.1 || ^8.5, and `laranail/console` is in `require`. What the copy left behind was a second
 * place that knew how to write past `validateName()`, free to drift from the first.
 *
 * What remains here is genuinely this package's own: applying a signature from
 * `namespacedSignature()` rather than Laravel's `$signature`, and the option/argument accessors.
 */
trait SupportsNamespacedNames
{
    use CanonicalNamespacedNames;

    public function __construct()
    {
        parent::__construct();

        $signature = $this->namespacedSignature();

        if ($signature !== '') {
            $this->applyNamespacedSignature($signature);
        }

        $aliases = $this->declaredCommandAliases();

        if ($aliases !== []) {
            $this->setAliases($aliases);
        }
    }

    /**
     * The consuming command's own `$commandAliases`, if it declares one.
     *
     * Deliberately NOT a property on this trait, for the same reason `namespacedSignature()` is a
     * method: a trait cannot declare a property that the using class also declares with a different
     * default -- PHP rejects the composition outright. Declaring it here made "a command that wants
     * aliases declares its own list" a compile-time fatal rather than the documented usage.
     *
     * @return list<string>
     */
    private function declaredCommandAliases(): array
    {
        if (! property_exists($this, 'commandAliases') || ! is_array($this->commandAliases)) {
            return [];
        }

        // Filtered rather than cast: the property is the consuming command's, so its contents are
        // not this trait's to assume. A stray null would reach Symfony's setAliases() as a type
        // error at boot, which is the failure mode this whole method exists to avoid.
        return array_values(array_filter(
            $this->commandAliases,
            static fn (mixed $alias): bool => is_string($alias) && $alias !== '',
        ));
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

        // setName() comes from the canonical trait, which does the write past validateName().
        $this->setName($name);

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
