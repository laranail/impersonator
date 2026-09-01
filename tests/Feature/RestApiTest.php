<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\RecordImpersonationTrail;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 10);
    config()->set('laranail.impersonator.limits.state_cache.ttl', 0);

    // The API is off by default, so a suite testing it has to switch it on — which is the point.
    config()->set('laranail.impersonator.api.enabled', true);
    config()->set('laranail.impersonator.api.middleware', ['api']);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    // Routes are loaded at boot, so the group has to be registered again once config changed.
    $this->app->booted(fn (): null => null);
    require dirname(__DIR__, 2).'/routes/api.php';

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

function apiUrl(string $path): string
{
    return '/impersonator/api/v1/'.ltrim($path, '/');
}

// ── the API is opt-in ───────────────────────────────────────────────────────

// ── start ───────────────────────────────────────────────────────────────────

it('starts an impersonation and returns 201', function (): void {
    $response = $this->postJson(apiUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
        'reason' => 'Ticket #4182',
    ]);

    $response->assertCreated()
        ->assertJsonPath('data.pending', false)
        ->assertJsonPath('data.impersonation.reason', 'Ticket #4182')
        ->assertJsonPath('data.impersonation.mode', 'full');

    expect(Impersonator::isImpersonating())->toBeTrue();
});

it('returns a pending handoff with an accept url for the token driver', function (): void {
    // A pending handoff has not impersonated anybody; a client treating it as live would show "now
    // impersonating" for a session that was never created.
    config()->set('laranail.impersonator.driver', 'token');
    config()->set('laranail.impersonator.urls.base_domain', 'app.example.com');

    $response = $this->postJson(apiUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
    ]);

    $response->assertCreated()->assertJsonPath('data.pending', true);

    expect($response->json('data.accept_url'))->toStartWith('https://app.example.com/')
        ->and(Impersonator::isImpersonating())->toBeFalse();
});

it('validates the body exactly as the html endpoint does', function (): void {
    // The API extends the same Form Request, so two copies of these rules cannot drift.
    $this->postJson(apiUrl('impersonations'), [
        'target_type' => 'App\\Models\\Anything',
        'target_id' => '1',
    ])->assertStatus(422)->assertJsonValidationErrors('target_type');

    $this->postJson(apiUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
        'mode' => 'god',
    ])->assertStatus(422)->assertJsonValidationErrors('mode');

    $this->postJson(apiUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
        'redirect_to' => 'https://evil.example',
    ])->assertStatus(422)->assertJsonValidationErrors('redirect_to');
});

it('refuses self-impersonation with a 403 and a reason code', function (): void {
    $this->postJson(apiUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->admin->getKey(),
    ])->assertForbidden()->assertJsonPath('reason', 'self_impersonation');
});

// ── current and leave ───────────────────────────────────────────────────────

it('reports the current impersonation', function (): void {
    Impersonator::enter($this->target, mode: 'read_only');

    $this->getJson(apiUrl('impersonations/current'))
        ->assertOk()
        ->assertJsonPath('data.mode', 'read_only')
        ->assertJsonPath('data.active', true);
});

it('returns 204 rather than 404 when not impersonating', function (): void {
    // The resource is the caller's own state: it exists and is empty. A 404 would suggest the
    // endpoint was wrong.
    $this->getJson(apiUrl('impersonations/current'))->assertNoContent();
});

it('leaves through the api', function (): void {
    Impersonator::enter($this->target);

    $this->deleteJson(apiUrl('impersonations/current'))
        ->assertOk()
        ->assertJsonPath('data.ended_by', 'left');

    expect(Impersonator::isImpersonating())->toBeFalse();
});

it('returns 204 when there was nothing to leave', function (): void {
    $this->deleteJson(apiUrl('impersonations/current'))->assertNoContent();
});

// ── revoke ──────────────────────────────────────────────────────────────────

it('revokes and says the session is not yet terminated', function (): void {
    // For a session credential the flag is what the target's next request sees, so the response says
    // "recorded" rather than implying the session is already gone.
    $auditId = Impersonator::enter($this->target)->auditId();

    $this->postJson(apiUrl("impersonations/{$auditId}/revoke"), ['note' => 'Escalation'])
        ->assertOk()
        ->assertJsonPath('meta.terminated', false)
        ->assertJsonPath('data.revoked_at', fn ($value): bool => $value !== null);

    expect(app(AuditStore::class)->find($auditId)->isRevoked())->toBeTrue();
});

it('bounds the revocation note', function (): void {
    $auditId = Impersonator::enter($this->target)->auditId();

    $this->postJson(apiUrl("impersonations/{$auditId}/revoke"), ['note' => str_repeat('x', 501)])
        ->assertStatus(422)->assertJsonValidationErrors('note');
});

// ── audits ──────────────────────────────────────────────────────────────────

it('lists impersonations newest first', function (): void {
    $first = Impersonator::enter($this->target)->auditId();
    Impersonator::leave();
    $second = Impersonator::enter($this->target)->auditId();

    $response = $this->getJson(apiUrl('audits'))->assertOk();

    expect($response->json('data.0.id'))->toBe($second)
        ->and($response->json('data.1.id'))->toBe($first)
        ->and($response->json('meta.total'))->toBe(2);
});

it('never emits a credential hash or session id in a listing', function (): void {
    // The likeliest place for a leak, because it is what dashboards and CSV dumps are built on.
    $auditId = Impersonator::enter($this->target)->auditId();
    $row = ImpersonationAudit::query()->findOrFail($auditId);

    $body = $this->getJson(apiUrl('audits'))->assertOk()->content();

    expect($body)->not->toContain((string) $row->getAttribute('credential_hash'))
        ->and($body)->not->toContain((string) $row->getAttribute('session_id'))
        ->and($body)->not->toContain('credential_hash')
        ->and($body)->not->toContain('session_id');
});

it('never emits a credential on the detail endpoint either', function (): void {
    $auditId = Impersonator::enter($this->target)->auditId();
    $row = ImpersonationAudit::query()->findOrFail($auditId);

    $body = $this->getJson(apiUrl("audits/{$auditId}"))->assertOk()->content();

    expect($body)->not->toContain((string) $row->getAttribute('credential_hash'))
        ->and($body)->not->toContain((string) $row->getAttribute('session_id'));
});

it('filters by mode, target and active state', function (): void {
    $other = User::create(['name' => 'Other']);

    Impersonator::enter($this->target, mode: 'read_only');
    Impersonator::leave();
    Impersonator::enter($other, mode: 'full');

    expect($this->getJson(apiUrl('audits?mode=read_only'))->json('meta.total'))->toBe(1)
        ->and($this->getJson(apiUrl('audits?target=user:'.$other->getKey()))->json('meta.total'))->toBe(1)
        ->and($this->getJson(apiUrl('audits?active=1'))->json('meta.total'))->toBe(1)
        ->and($this->getJson(apiUrl('audits?active=0'))->json('meta.total'))->toBe(1);
});

it('rejects an unknown filter value rather than returning an empty page', function (): void {
    // A silently empty page reads as "no impersonations happened", which is the worst possible
    // answer for an audit query.
    $this->getJson(apiUrl('audits?mode=god'))->assertStatus(422)->assertJsonValidationErrors('mode');
    $this->getJson(apiUrl('audits?ended_by=vanished'))->assertStatus(422);
});

it('caps the page size rather than honouring an unbounded request', function (): void {
    config()->set('laranail.impersonator.api.max_per_page', 5);

    $this->getJson(apiUrl('audits?per_page=1000'))->assertStatus(422);
    $this->getJson(apiUrl('audits?per_page=5'))->assertOk();
});

it('includes the trail on the detail endpoint', function (): void {
    Route::middleware(['web', RecordImpersonationTrail::class])
        ->get('/app/page', fn (): string => 'page');

    $auditId = Impersonator::enter($this->target)->auditId();
    $this->get('/app/page');

    $this->getJson(apiUrl("audits/{$auditId}"))
        ->assertOk()
        ->assertJsonPath('meta.trail_events', 1)
        ->assertJsonPath('trail.0.path', '/app/page');
});

it('404s for an unknown audit row rather than leaking an internal error', function (): void {
    // AuditRowMissing means state was lost between opening a row and acting on it — a bug signal. An
    // id typed by a client that matches nothing is an ordinary not-found.
    $this->getJson(apiUrl('audits/nope'))->assertNotFound();
    $this->get(apiUrl('audits/nope/export'))->assertNotFound();
});

it('exports as a download', function (): void {
    $auditId = Impersonator::enter($this->target)->auditId();

    $response = $this->get(apiUrl("audits/{$auditId}/export"))->assertOk();

    expect($response->headers->get('content-type'))->toContain('application/json')
        ->and($response->headers->get('content-disposition'))->toContain('impersonation-'.$auditId.'.json');
});

it('exports as csv when asked', function (): void {
    $auditId = Impersonator::enter($this->target)->auditId();

    $response = $this->get(apiUrl("audits/{$auditId}/export?format=csv"))->assertOk();

    expect($response->headers->get('content-type'))->toContain('text/csv')
        ->and($response->getContent())->toContain('section,field,value');
});

// ── authorisation ───────────────────────────────────────────────────────────

it('requires authentication to start', function (): void {
    Auth::guard('web')->logout();

    $this->postJson(apiUrl('impersonations'), [
        'target_type' => 'user',
        'target_id' => (string) $this->target->getKey(),
    ])->assertForbidden();
});

it('requires the audit permission to read the trail', function (): void {
    Auth::guard('web')->logout();

    $this->getJson(apiUrl('audits'))->assertForbidden();
});

it('throttles the api', function (): void {
    config()->set('laranail.impersonator.rate_limiting.api.attempts', 2);

    $payload = ['target_type' => 'user', 'target_id' => '99999'];

    $this->postJson(apiUrl('impersonations'), $payload)->assertNotFound();
    $this->postJson(apiUrl('impersonations'), $payload)->assertNotFound();
    $this->postJson(apiUrl('impersonations'), $payload)->assertStatus(429);
});
