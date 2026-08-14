<?php

declare(strict_types=1);

use Simtabi\Laranail\Enumerator\Contracts\Translatable;
use Simtabi\Laranail\Impersonator\Core\Enums\ApprovalState;
use Simtabi\Laranail\Impersonator\Core\Enums\CredentialType;
use Simtabi\Laranail\Impersonator\Core\Enums\Criticality;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;

/*
| Enum labels, now resolved through laranail/enumerator.
|
| The distinction these tests defend: the **value** is the contract and the **label** is not. Values
| are persisted, returned by the API and matched in logs, so translating one would break a consumer
| silently. Labels are display text and may be localised freely.
|
| **A unit test on purpose — no application is booted here.** That is the assertion, not an
| accident: these enums live in Core, and everything below has to hold with no container, no config
| and no translator. The two cases that genuinely need a translator are in
| tests/Feature/EnumTranslationTest.php.
*/

it('keeps every label byte-identical to the hand-written version', function (
    string $enum,
    array $expected,
): void {
    // The conversion replaced a `match` with an attribute lookup. Output must not have moved — this
    // is a refactor, and a label that shifted would surface as changed UI nobody asked for.
    foreach ($expected as $case => $label) {
        expect($enum::from($case)->label())->toBe($label);
    }
})->with([
    'EndReason' => [EndReason::class, [
        'left' => 'Left',
        'expired' => 'Expired',
        'revoked' => 'Revoked',
        'session_lost' => 'Session lost',
    ]],
    'ApprovalState' => [ApprovalState::class, [
        'pending' => 'Awaiting approval',
        'approved' => 'Approved',
        'consumed' => 'Used',
        'denied' => 'Denied',
        'expired' => 'Expired',
    ]],
    'CredentialType' => [CredentialType::class, [
        'session' => 'Session',
        'sanctum_token' => 'Sanctum token',
        'passport_token' => 'Passport token',
        'jwt' => 'JWT',
    ]],
]);

it('pins the translation slug rather than deriving it', function (): void {
    // `IsTranslatable::translationSlug()` defaults to `class_basename()` — a Laravel helper called
    // with no `function_exists()` guard, the only unguarded one in that trait. Overriding it is what
    // keeps these enums usable with no Laravel present, and stops a class rename silently relocating
    // every translation key so labels fall back to English without saying so.
    expect(EndReason::translationSlug())->toBe('end_reason')
        ->and(ApprovalState::translationSlug())->toBe('approval_state')
        ->and(CredentialType::translationSlug())->toBe('credential_type')
        ->and(EndReason::translationNamespace())->toBe('laranail-impersonator');
});

it('builds a translation key an application can actually target', function (): void {
    // Published shape: an application localising these needs to know where to put the keys.
    expect(EndReason::translationKey('revoked'))->toBe('laranail-impersonator::enums.end_reason.revoked')
        ->and(ApprovalState::translationKey('pending', 'description'))
        ->toBe('laranail-impersonator::enums.approval_state.pending.description');
});

it('keeps isInvoluntary in its fail-safe open form', function (): void {
    // Deliberately NOT expressed as an allowlist of involuntary cases, which is what enumerator's
    // HasGrouping would encourage: an allowlist defaults a future case to *voluntary*, and getting
    // that wrong in this domain understates what happened to somebody's account.
    expect(EndReason::Left->isInvoluntary())->toBeFalse();

    foreach (EndReason::cases() as $case) {
        if ($case !== EndReason::Left) {
            expect($case->isInvoluntary())->toBeTrue();
        }
    }
});

it('leaves Criticality untranslated and unlabelled', function (): void {
    // `decision()` returns machine-readable log values, not display text. Translating them would
    // corrupt the failure report, so this enum deliberately did not adopt the trait.
    expect(Criticality::class)->not->toImplement(Translatable::class)
        ->and(Criticality::Critical->decision())->toBe('crashed')
        ->and(Criticality::Degradable->decision())->toBe('degraded-and-continued');
});
