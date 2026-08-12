<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;

/*
| Enum labels once a translator exists.
|
| The counterpart to tests/Unit/Enums/TranslatableLabelsTest.php, which pins the same labels with no
| application booted at all. Split because the property being asserted is different: there, that Core
| degrades gracefully; here, that a registered translation actually wins.
*/

it('resolves a label from the translator when one is registered', function (): void {
    // The point of the change. Registered under the key above, the translation wins over `#[Label]`.
    app('translator')->addLines(
        ['enums.end_reason.revoked' => 'Ended by an administrator'],
        'en',
        'impersonator',
    );

    expect(EndReason::Revoked->label())->toBe('Ended by an administrator')
        // Untranslated cases still fall through to their attribute.
        ->and(EndReason::Left->label())->toBe('Left');
});

it('never translates the value, only the label', function (): void {
    // The contract. A consumer branching on `ended_by` must not be affected by a locale.
    app('translator')->addLines(
        ['enums.end_reason.revoked' => 'Beendet'],
        'en',
        'impersonator',
    );

    expect(EndReason::Revoked->value)->toBe('revoked')
        ->and(EndReason::Revoked->label())->toBe('Beendet');
});
