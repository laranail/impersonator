<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Core\Exceptions\InvalidMode;

it('names the three built-in modes', function (): void {
    expect(Mode::builtIn())->toBe(['read_only', 'limited', 'full'])
        ->and(Mode::readOnly()->name)->toBe('read_only')
        ->and(Mode::limited()->name)->toBe('limited')
        ->and(Mode::full()->name)->toBe('full');
});

it('accepts a custom mode name, because modes are an extension point', function (): void {
    expect(Mode::of('billing_support')->name)->toBe('billing_support');
});

it('rejects a malformed mode name', function (string $name): void {
    Mode::of($name);
})->with(['Read_Only', 'read-only', '9lives', '', 'read only', 'réad'])
    ->throws(InvalidMode::class);

it('compares against a string or another mode', function (): void {
    expect(Mode::full()->is('full'))->toBeTrue()
        ->and(Mode::full()->is(Mode::full()))->toBeTrue()
        ->and(Mode::full()->isNot(Mode::readOnly()))->toBeTrue();
});

it('derives its gating permission from a template', function (): void {
    expect(Mode::readOnly()->permission())->toBe('impersonator.mode.read_only')
        ->and(Mode::full()->permission('acme.imp.%s'))->toBe('acme.imp.full');
});

it('stringifies to its name', function (): void {
    expect((string) Mode::limited())->toBe('limited');
});
