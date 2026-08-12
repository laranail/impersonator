<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Values\Decision;

it('allows with no code or reason', function (): void {
    $decision = Decision::allow();

    expect($decision->allowed)->toBeTrue()
        ->and($decision->denied())->toBeFalse()
        ->and($decision->code)->toBeNull();
});

it('carries a machine-readable code on every denial', function (): void {
    $decision = Decision::deny(Decision::PROTECTED_ROLE, 'Target holds a protected role.', ['role' => 'super-admin']);

    expect($decision->denied())->toBeTrue()
        ->and($decision->code)->toBe('protected_role')
        ->and($decision->context)->toBe(['role' => 'super-admin']);
});

it('returns the first denial intact so the specific rule is known', function (): void {
    $decision = Decision::all([
        static fn (): Decision => Decision::allow(),
        static fn (): Decision => Decision::deny(Decision::REASON_REQUIRED, 'A reason is required.'),
        static fn (): Decision => Decision::deny(Decision::RATE_LIMITED, 'Too many attempts.'),
    ]);

    expect($decision->code)->toBe('reason_required');
});

it('short-circuits so later checks never run after a denial', function (): void {
    $ran = false;

    Decision::all([
        static fn (): Decision => Decision::deny(Decision::DISABLED, 'Impersonation is disabled.'),
        static function () use (&$ran): Decision {
            $ran = true;

            return Decision::allow();
        },
    ]);

    expect($ran)->toBeFalse();
});

it('allows when every check passes', function (): void {
    expect(Decision::all([
        static fn (): Decision => Decision::allow(),
        static fn (): Decision => Decision::allow(),
    ])->allowed)->toBeTrue();
});

it('allows an empty check list', function (): void {
    expect(Decision::all([])->allowed)->toBeTrue();
});
