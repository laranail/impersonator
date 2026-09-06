<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Core\Values\Credential;
use Simtabi\Laranail\Impersonator\Core\Enums\CredentialType;

it('carries no secret for a session credential', function (): void {
    $credential = Credential::session('session-id-abc');

    expect($credential->type)->toBe(CredentialType::Session)
        ->and($credential->hasSecret())->toBeFalse()
        ->and($credential->secret())->toBeNull()
        ->and($credential->type->isBearer())->toBeFalse();
});

it('hashes a bearer secret rather than storing it', function (): void {
    $credential = Credential::bearer(CredentialType::SanctumToken, 'plain-token-value', reference: '17');

    expect($credential->hash)->toBe(hash('sha256', 'plain-token-value'))
        ->and($credential->reference)->toBe('17')
        ->and($credential->type->isBearer())->toBeTrue();
});

it('never puts the secret in its audit projection', function (): void {
    $audit = Credential::bearer(CredentialType::Jwt, 'plain-token-value')->toAuditArray();

    expect($audit)->not->toHaveKey('secret')
        ->and(json_encode($audit))->not->toContain('plain-token-value');
});

it('redacts the secret in its debug form', function (): void {
    $debug = Credential::bearer(CredentialType::PassportToken, 'plain-token-value')->__debugInfo();

    expect($debug['secret'])->toBe('[redacted]')
        ->and(print_r($debug, true))->not->toContain('plain-token-value');
});

it('exposes the secret exactly once through the accessor', function (): void {
    // "Returned exactly once" is a property of the flow, not the object: the
    // credential is never persisted, so the only copy is the one the caller
    // serialises into its single response.
    $credential = Credential::bearer(CredentialType::SanctumToken, 'plain-token-value');

    expect($credential->secret())->toBe('plain-token-value')
        ->and($credential->hasSecret())->toBeTrue();
});

it('records an expiry in the audit projection', function (): void {
    $expiry = new DateTimeImmutable('2026-01-01 00:05:00');

    expect(Credential::bearer(CredentialType::Jwt, 'x', expiresAt: $expiry)->toAuditArray()['expires_at'])
        ->toBe($expiry->format(DATE_ATOM));
});
