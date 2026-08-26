<?php

declare(strict_types=1);

use Illuminate\Console\Command as LaravelCommand;
use Simtabi\Laranail\Impersonator\Laravel\Commands\Concerns\SupportsNamespacedNames;

/*
| Conformance for this package's namespaced-naming trait.
|
| Unlike the other copies in the family, this one is constructor-driven: the name comes from
| namespacedSignature() rather than Laravel's $signature, which is what lets it skip validateName()
| without nulling or reflecting anything away first.
|
| The reflection write beneath it is no longer duplicated here — it composes laranail/console's
| canonical trait, which this package already requires. These tests pin the behaviour that
| composition has to preserve.
*/

it('takes its name from the namespaced signature', function (): void {
    $command = new class extends LaravelCommand
    {
        use SupportsNamespacedNames;

        protected function namespacedSignature(): string
        {
            return 'laranail::impersonator.doctor {--reason=}';
        }
    };

    expect($command->getName())->toBe('laranail::impersonator.doctor');
});

it('parses the signature into a definition', function (): void {
    $command = new class extends LaravelCommand
    {
        use SupportsNamespacedNames;

        protected function namespacedSignature(): string
        {
            return 'laranail::impersonator.prune {user} {--force}';
        }
    };

    expect($command->getDefinition()->hasArgument('user'))->toBeTrue()
        ->and($command->getDefinition()->hasOption('force'))->toBeTrue();
});

it('is inert when no signature is declared', function (): void {
    // The default returns '', and a command that never overrides it must construct cleanly rather
    // than trying to parse an empty signature.
    $command = new class extends LaravelCommand
    {
        use SupportsNamespacedNames;
    };

    expect($command->getName())->not->toBe('laranail::impersonator.doctor');
});

it('applies a declared alias list', function (): void {
    $command = new class extends LaravelCommand
    {
        use SupportsNamespacedNames;

        protected array $commandAliases = ['laranail::impersonator.dr'];

        protected function namespacedSignature(): string
        {
            return 'laranail::impersonator.doctor';
        }
    };

    expect($command->getAliases())->toBe(['laranail::impersonator.dr']);
});

it('does not fatal without an alias list', function (): void {
    // The bug that made these copies worth pinning: reading $commandAliases without declaring it
    // throws for every command that does not — at boot, for the whole application.
    $command = new class extends LaravelCommand
    {
        use SupportsNamespacedNames;

        protected function namespacedSignature(): string
        {
            return 'laranail::impersonator.quiet';
        }
    };

    expect($command->getAliases())->toBe([]);
});
