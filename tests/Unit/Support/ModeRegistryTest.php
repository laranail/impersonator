<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Contracts\ModeEnforcer;
use Simtabi\Laranail\Impersonator\Core\Exceptions\InvalidMode;
use Simtabi\Laranail\Impersonator\Core\Support\ModeRegistry;
use Simtabi\Laranail\Impersonator\Core\Values\AttemptedAction;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;

/**
 * A stand-in enforcer. The built-in three arrive with the mode layer; the
 * registry's own behaviour is independent of them and testable now.
 */
function fakeEnforcer(string $mode, bool $guardsPersistence = false): ModeEnforcer
{
    return new readonly class($mode, $guardsPersistence) implements ModeEnforcer
    {
        public function __construct(
            private string $mode,
            private bool $guardsPersistence,
        ) {}

        public function mode(): string
        {
            return $this->mode;
        }

        public function check(AttemptedAction $action, ImpersonationSession $session): Decision
        {
            return Decision::allow();
        }

        public function guardsPersistence(): bool
        {
            return $this->guardsPersistence;
        }

        public function describe(): string
        {
            return "the {$this->mode} envelope";
        }
    };
}

it('starts empty', function (): void {
    expect((new ModeRegistry)->names())->toBe([])
        ->and((new ModeRegistry)->has('full'))->toBeFalse();
});

it('registers enforcers from the constructor', function (): void {
    $registry = new ModeRegistry([fakeEnforcer('read_only'), fakeEnforcer('full')]);

    expect($registry->names())->toBe(['read_only', 'full']);
});

it('resolves a registered mode to a value object', function (): void {
    $registry = new ModeRegistry([fakeEnforcer('limited')]);

    expect($registry->resolve('limited'))->toEqual(Mode::limited());
});

it('refuses an unregistered mode instead of falling back', function (): void {
    // A typo in default_mode that quietly resolved to `full` would hand every
    // operator unrestricted access, so this has to be loud.
    new ModeRegistry([fakeEnforcer('read_only')])->resolve('ful');
})->throws(InvalidMode::class, 'is not registered');

it('names the available modes in the failure message', function (): void {
    expect(fn (): Mode => new ModeRegistry([fakeEnforcer('read_only')])->resolve('nope'))
        ->toThrow(InvalidMode::class, 'read_only');
});

it('returns the enforcer for a mode value object or a string', function (): void {
    $registry = new ModeRegistry([fakeEnforcer('full')]);

    expect($registry->enforcer('full')->mode())->toBe('full')
        ->and($registry->enforcer(Mode::full())->mode())->toBe('full');
});

it('lets a later registration replace an earlier one', function (): void {
    $registry = new ModeRegistry([fakeEnforcer('full', guardsPersistence: false)]);
    $registry->register(fakeEnforcer('full', guardsPersistence: true));

    expect($registry->names())->toBe(['full'])
        ->and($registry->enforcer('full')->guardsPersistence())->toBeTrue();
});

it('describes every registered mode', function (): void {
    $registry = new ModeRegistry([fakeEnforcer('read_only'), fakeEnforcer('full')]);

    expect($registry->descriptions())->toBe([
        'read_only' => 'the read_only envelope',
        'full' => 'the full envelope',
    ]);
});
