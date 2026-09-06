<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Core\Values\Guards;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ExtensionPolicy;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;

/*
| The extension rules, with no container and no database.
|
| Worth having at this level because the interesting cases are all about arithmetic against a
| clock, and proving them through HTTP would mean travelling time on every one.
*/

function anImpersonation(
    string $startedAt = '2026-08-12 10:00:00',
    ?string $expiresAt = '2026-08-12 10:10:00',
    int $extensions = 0,
    ?string $endedAt = null,
    ?string $revokedAt = null,
): ImpersonationSession {
    return new ImpersonationSession(
        auditId: '01hq000000000000000000000',
        impersonator: new Identity('user', 1),
        target: new Identity('user', 2),
        mode: Mode::of(Mode::FULL),
        guards: new Guards('web', 'web'),
        driver: 'session',
        adapter: 'session',
        startedAt: new DateTimeImmutable($startedAt),
        endedAt: $endedAt === null ? null : new DateTimeImmutable($endedAt),
        endedBy: $endedAt === null ? null : EndReason::Left,
        expiresAt: $expiresAt === null ? null : new DateTimeImmutable($expiresAt),
        revokedAt: $revokedAt === null ? null : new DateTimeImmutable($revokedAt),
        extensions: $extensions,
    );
}

function instant(string $time): DateTimeImmutable
{
    return new DateTimeImmutable($time);
}

it('grants a window and reports what it added', function (): void {
    $grant = (new ExtensionPolicy)->evaluate(anImpersonation(), instant('2026-08-12 10:05:00'));

    expect($grant->granted())->toBeTrue()
        ->and($grant->expiresAt?->format('H:i'))->toBe('10:20')
        ->and($grant->seconds())->toBe(600);
});

it('refuses when extension is switched off', function (): void {
    $grant = new ExtensionPolicy(enabled: false)->evaluate(anImpersonation(), instant('2026-08-12 10:05:00'));

    expect($grant->denied())->toBeTrue()
        ->and($grant->decision->code)->toBe(Decision::EXTENSION_DISABLED)
        ->and($grant->seconds())->toBe(0);
});

it('refuses once the count is spent', function (): void {
    $policy = new ExtensionPolicy(max: 2);

    expect($policy->evaluate(anImpersonation(extensions: 1), instant('2026-08-12 10:05:00'))->granted())->toBeTrue()
        ->and($policy->evaluate(anImpersonation(extensions: 2), instant('2026-08-12 10:05:00'))->decision->code)
        ->toBe(Decision::EXTENSION_LIMIT);
});

it('allows unlimited extensions when max is null', function (): void {
    // Deliberately absurd count: null must mean unbounded rather than a large default.
    $grant = new ExtensionPolicy(max: null, maxTotalMinutes: null)
        ->evaluate(anImpersonation(extensions: 500), instant('2026-08-12 10:05:00'));

    expect($grant->granted())->toBeTrue();
});

it('clamps the last extension to the ceiling instead of refusing it', function (): void {
    // 25 minutes total, expiring at 10:20, asking for 10 more. Four are available, so four is
    // what should be granted — refusing would strand an allowance the config does permit.
    $grant = new ExtensionPolicy(minutes: 10, maxTotalMinutes: 25)
        ->evaluate(anImpersonation(expiresAt: '2026-08-12 10:20:00'), instant('2026-08-12 10:19:00'));

    expect($grant->granted())->toBeTrue()
        ->and($grant->expiresAt?->format('H:i'))->toBe('10:25')
        ->and($grant->seconds())->toBe(300);
});

it('refuses once the ceiling is reached', function (): void {
    $grant = new ExtensionPolicy(maxTotalMinutes: 30)
        ->evaluate(anImpersonation(expiresAt: '2026-08-12 10:30:00'), instant('2026-08-12 10:29:00'));

    expect($grant->denied())->toBeTrue()
        ->and($grant->decision->code)->toBe(Decision::EXTENSION_CEILING);
});

it('bounds total time even when the count is unlimited', function (): void {
    // The property that makes the pair of limits worth having: neither alone is sufficient.
    $grant = new ExtensionPolicy(max: null, maxTotalMinutes: 20)
        ->evaluate(anImpersonation(expiresAt: '2026-08-12 10:20:00', extensions: 99), instant('2026-08-12 10:19:00'));

    expect($grant->decision->code)->toBe(Decision::EXTENSION_CEILING);
});

it('holds the window shut until the final minutes when configured', function (): void {
    $policy = new ExtensionPolicy(withinMinutes: 3);

    expect($policy->evaluate(anImpersonation(), instant('2026-08-12 10:05:00'))->decision->code)
        ->toBe(Decision::EXTENSION_TOO_EARLY)
        ->and($policy->evaluate(anImpersonation(), instant('2026-08-12 10:08:00'))->granted())->toBeTrue();
});

it('refuses a session that has already ended', function (): void {
    $grant = (new ExtensionPolicy)->evaluate(
        anImpersonation(endedAt: '2026-08-12 10:06:00'),
        instant('2026-08-12 10:07:00'),
    );

    expect($grant->decision->code)->toBe(Decision::SESSION_TERMINATED);
});

it('refuses a revoked session that has not yet been closed', function (): void {
    // The gap between an administrator pulling the switch and the target session's next
    // request. Extending inside it would let an operator outrun their own revocation.
    $grant = (new ExtensionPolicy)->evaluate(
        anImpersonation(revokedAt: '2026-08-12 10:06:00'),
        instant('2026-08-12 10:07:00'),
    );

    expect($grant->decision->code)->toBe(Decision::SESSION_TERMINATED);
});

it('refuses to resurrect an impersonation that already expired', function (): void {
    $grant = (new ExtensionPolicy)->evaluate(anImpersonation(), instant('2026-08-12 10:11:00'));

    expect($grant->decision->code)->toBe(Decision::SESSION_TERMINATED);
});

it('has nothing to extend when there is no expiry', function (): void {
    $grant = (new ExtensionPolicy)->evaluate(anImpersonation(expiresAt: null), instant('2026-08-12 10:05:00'));

    expect($grant->decision->code)->toBe(Decision::EXTENSION_CEILING);
});

it('reports the ceiling and the remaining count for a UI', function (): void {
    $policy = new ExtensionPolicy(max: 3, maxTotalMinutes: 60);

    expect($policy->ceilingFor(anImpersonation())->format('H:i'))->toBe('11:00')
        ->and($policy->remainingFor(anImpersonation(extensions: 1)))->toBe(2)
        ->and($policy->remainingFor(anImpersonation(extensions: 9)))->toBe(0)
        ->and(new ExtensionPolicy(max: null)->remainingFor(anImpersonation()))->toBeNull()
        ->and(new ExtensionPolicy(maxTotalMinutes: null)->ceilingFor(anImpersonation()))->toBeNull();
});

it('counts each extension on the session it returns', function (): void {
    $extended = anImpersonation()->extended(instant('2026-08-12 10:20:00'));

    expect($extended->extensions)->toBe(1)
        ->and($extended->expiresAt?->format('H:i'))->toBe('10:20')
        ->and($extended->extended(instant('2026-08-12 10:30:00'))->extensions)->toBe(2)
        // Everything else has to survive the transition, or leaving after an extension loses
        // the audit id the whole trail is correlated by.
        ->and($extended->auditId)->toBe(anImpersonation()->auditId)
        ->and($extended->startedAt->format('H:i'))->toBe('10:00');
});

it('floors the remaining countdown at zero', function (): void {
    // A negative remainder renders as a number counting the wrong way.
    expect(anImpersonation()->remainingSeconds(instant('2026-08-12 10:05:00')))->toBe(300)
        ->and(anImpersonation()->remainingSeconds(instant('2026-08-12 10:30:00')))->toBe(0)
        ->and(anImpersonation(expiresAt: null)->remainingSeconds(instant('2026-08-12 10:05:00')))->toBeNull();
});

it('carries the extension count through a cache snapshot', function (): void {
    // The middleware rebuilds from this on every request, so a count lost here resets the cap.
    $snapshot = anImpersonation(extensions: 2)->toSnapshot();

    expect(ImpersonationSession::fromSnapshot($snapshot)->extensions)->toBe(2)
        ->and(ImpersonationSession::fromSnapshot(['id' => 'x'] + $snapshot)->extensions)->toBe(2);
});
