<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;
use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Exceptions\TokenRejected;
use Simtabi\Laranail\Impersonator\Core\Contracts\TokenRepository;
use Simtabi\Laranail\Impersonator\Core\Events\HandoffTokenIssued;
use Simtabi\Laranail\Impersonator\Core\Events\HandoffTokenRedeemed;
use Simtabi\Laranail\Impersonator\Core\Events\HandoffTokenRejected;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationStarted;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationOutcome;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('laranail.impersonator.driver', 'token');
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 10);
    config()->set('laranail.impersonator.urls.base_domain', 'tenant.example.com');
    config()->set('app.url', 'https://admin.example.com');

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

/**
 * Enter and pull the raw token back out of the accept URL.
 *
 * The URL is the only place the plaintext exists, which is exactly the property under test.
 *
 * @return array{0: ImpersonationOutcome, 1: string}
 */
function issueToken(User $target): array
{
    $outcome = Impersonator::enter($target);
    $token = rawurldecode(basename(parse_url($outcome->acceptUrl(), PHP_URL_PATH) ?: ''));

    return [$outcome, $token];
}

// ── issuing ─────────────────────────────────────────────────────────────────

it('returns a pending outcome rather than impersonating anybody', function (): void {
    // Nobody is impersonating until the URL is followed; treating a pending handoff as a
    // live session is how a UI shows "now impersonating" for something that never happened.
    [$outcome] = issueToken($this->target);

    expect($outcome->pending)->toBeTrue()
        ->and($outcome->isStarted())->toBeFalse()
        ->and(Impersonator::isImpersonating())->toBeFalse()
        ->and(Auth::guard('web')->id())->toBe($this->admin->getKey());
});

it('builds an absolute accept URL on the tenant host', function (): void {
    [$outcome] = issueToken($this->target);

    expect($outcome->acceptUrl())->toStartWith('https://tenant.example.com/impersonator/accept/');
});

it('opens an audit row at issue time, so an unused link still leaves a trace', function (): void {
    [$outcome] = issueToken($this->target);

    expect(app(AuditStore::class)->find($outcome->auditId()))->not->toBeNull();
});

it('emits a token-issued event that carries no token value', function (): void {
    // Events are serialised into queues and logs, which is exactly where a live credential
    // must never appear.
    Event::fake([HandoffTokenIssued::class]);

    Impersonator::enter($this->target);

    Event::assertDispatched(HandoffTokenIssued::class, fn (HandoffTokenIssued $e): bool => ! str_contains(json_encode($e->session->toArray()) ?: '', 'accept/'));
});

it('never stores the plaintext token', function (): void {
    [, $token] = issueToken($this->target);

    $rows = DB::table('impersonator_tokens')->get();

    expect($rows)->toHaveCount(1)
        ->and($rows[0]->token_hash)->toBe(hash('sha256', $token))
        ->and(json_encode($rows))->not->toContain($token);
});

it('generates a token of at least 32 bytes of entropy', function (): void {
    config()->set('laranail.impersonator.tokens.bytes', 8);
    [, $token] = issueToken($this->target);

    // The configured length has a floor: a token short enough to guess makes every other
    // control here pointless.
    expect(strlen(base64_decode(strtr($token, '-_', '+/'), true) ?: ''))->toBeGreaterThanOrEqual(32);
});

it('issues a distinct token every time', function (): void {
    [, $first] = issueToken($this->target);
    [, $second] = issueToken($this->target);

    expect($first)->not->toBe($second);
});

// ── redeeming ───────────────────────────────────────────────────────────────

it('authenticates the target when the token is redeemed', function (): void {
    [, $token] = issueToken($this->target);

    $outcome = Impersonator::complete($token, 'token');

    expect($outcome->isStarted())->toBeTrue()
        ->and(Auth::guard('web')->id())->toBe($this->target->getKey())
        ->and(Impersonator::isImpersonating())->toBeTrue();
});

it('emits redeemed and started together on a successful handoff', function (): void {
    // Faked before the driver is resolved: drivers capture the dispatcher at construction,
    // and the manager caches them, so a later fake would not be seen.
    Event::fake([HandoffTokenRedeemed::class, ImpersonationStarted::class]);

    [, $token] = issueToken($this->target);

    Impersonator::complete($token, 'token');

    Event::assertDispatched(HandoffTokenRedeemed::class);
    Event::assertDispatched(ImpersonationStarted::class);
});

it('works through the accept route', function (): void {
    [, $token] = issueToken($this->target);

    $this->get(route('impersonator.accept', ['token' => $token]))->assertRedirect('/');

    expect(Impersonator::isImpersonating())->toBeTrue();
});

// ── failing paths ───────────────────────────────────────────────────────────

it('refuses a replayed token', function (): void {
    // Single use is the whole contract: a token that survived one redemption could be
    // reused from a browser history entry or a proxy log.
    [, $token] = issueToken($this->target);
    Impersonator::complete($token, 'token');
    Impersonator::leave();

    expect(fn () => Impersonator::complete($token, 'token'))->toThrow(TokenRejected::class);
});

it('refuses an expired token', function (): void {
    config()->set('laranail.impersonator.tokens.ttl', 60);
    [, $token] = issueToken($this->target);

    $this->travel(61)->seconds();

    expect(fn () => Impersonator::complete($token, 'token'))->toThrow(TokenRejected::class);
});

it('does not mark an expired token as consumed', function (): void {
    // Otherwise the trail would read as a successful redemption.
    config()->set('laranail.impersonator.tokens.ttl', 60);
    [, $token] = issueToken($this->target);
    $this->travel(61)->seconds();

    try {
        Impersonator::complete($token, 'token');
    } catch (TokenRejected) {
        // expected
    }

    expect(DB::table('impersonator_tokens')->value('consumed_at'))->toBeNull();
});

it('refuses an unknown token', function (): void {
    expect(fn () => Impersonator::complete(str_repeat('a', 60), 'token'))
        ->toThrow(TokenRejected::class);
});

it('refuses a tampered token', function (): void {
    [, $token] = issueToken($this->target);

    expect(fn () => Impersonator::complete(strrev($token), 'token'))
        ->toThrow(TokenRejected::class);
});

it('gives every rejection the same message', function (): void {
    // Telling a caller a token merely expired tells them it was real.
    config()->set('laranail.impersonator.tokens.ttl', 60);
    [, $expiring] = issueToken($this->target);
    $this->travel(61)->seconds();

    $messages = [];

    foreach ([$expiring, str_repeat('z', 60)] as $candidate) {
        try {
            Impersonator::complete($candidate, 'token');
        } catch (TokenRejected $e) {
            $messages[] = $e->getMessage();
        }
    }

    expect($messages)->toHaveCount(2)
        ->and($messages[0])->toBe($messages[1])
        ->and($messages[0])->not->toContain('expired');
});

it('distinguishes rejections internally for the log', function (): void {
    Event::fake([HandoffTokenRejected::class]);

    try {
        Impersonator::complete(str_repeat('q', 60), 'token');
    } catch (TokenRejected) {
        // expected
    }

    Event::assertDispatched(
        HandoffTokenRejected::class,
        static fn (HandoffTokenRejected $e): bool => $e->reason === 'unknown',
    );
});

it('re-runs the authorization stack at redemption', function (): void {
    // The security-critical property: a permission can be withdrawn between minting a link
    // and following it, and a token that carried its own approval would still be honoured.
    [, $token] = issueToken($this->target);

    config()->set('laranail.impersonator.enabled', false);

    expect(fn () => Impersonator::complete($token, 'token'))->toThrow(ImpersonationDenied::class);
});

it('refuses a token whose target was deleted after it was issued', function (): void {
    [, $token] = issueToken($this->target);

    $this->target->delete();

    expect(fn () => Impersonator::complete($token, 'token'))->toThrow(ImpersonationDenied::class);
});

it('burns the token even when authorization then refuses', function (): void {
    // A token surviving a failed attempt could be retried until the window happened to
    // open. A fresh one is cheap.
    [, $token] = issueToken($this->target);
    config()->set('laranail.impersonator.enabled', false);

    try {
        Impersonator::complete($token, 'token');
    } catch (ImpersonationDenied) {
        // expected
    }

    config()->set('laranail.impersonator.enabled', true);

    expect(fn () => Impersonator::complete($token, 'token'))->toThrow(TokenRejected::class);
});

it('kills an in-flight token when the impersonation is revoked', function (): void {
    [$outcome, $token] = issueToken($this->target);

    Impersonator::revoke($outcome->auditId());
    app(TokenRepository::class)->revokeFor($outcome->auditId());

    expect(fn () => Impersonator::complete($token, 'token'))->toThrow(TokenRejected::class);
});

it('throttles the accept route', function (): void {
    config()->set('laranail.impersonator.rate_limiting.accept.attempts', 3);

    for ($i = 0; $i < 3; $i++) {
        $this->get(route('impersonator.accept', ['token' => str_repeat('a', 40)]));
    }

    $this->get(route('impersonator.accept', ['token' => str_repeat('a', 40)]))
        ->assertStatus(429);
});

it('rejects a route token that is too short to be one', function (): void {
    // Bounded before any hashing or database work happens.
    $this->get(route('impersonator.accept', ['token' => 'short']))->assertStatus(302);
});

// ── pruning ─────────────────────────────────────────────────────────────────

it('prunes expired, spent and revoked tokens but keeps live ones', function (): void {
    config()->set('laranail.impersonator.tokens.ttl', 60);

    [, $spent] = issueToken($this->target);
    Impersonator::complete($spent, 'token');
    Impersonator::leave();

    [, $expired] = issueToken($this->target);
    $this->travel(61)->seconds();

    [, $live] = issueToken($this->target);

    expect(DB::table('impersonator_tokens')->count())->toBe(3);

    $removed = app(TokenRepository::class)->pruneExpired();

    expect($removed)->toBe(2)
        ->and(app(TokenRepository::class)->isRedeemable($live))->toBeTrue();
});

it('exposes redeemability without consuming', function (): void {
    [, $token] = issueToken($this->target);

    expect(app(TokenRepository::class)->isRedeemable($token))->toBeTrue()
        ->and(app(TokenRepository::class)->isRedeemable($token))->toBeTrue()
        ->and(Impersonator::complete($token, 'token')->isStarted())->toBeTrue();
});

it('keeps the token in the accept URL from leaking any further', function (): void {
    // A handoff token has to ride in a URL, and a URL leaks where a request body does not: the
    // Referer on the next navigation, browser history, and access logs at every proxy between
    // here and the operator. The TTL and the single-use claim bound how long a leaked copy is
    // worth anything; these headers bound how many places it reaches.
    [, $token] = issueToken($this->target);

    $response = $this->get(route('impersonator.accept', ['token' => $token]))->assertRedirect('/');

    // `no-referrer`, not `same-origin`: the redirect target can be a different host than the one
    // that minted the link, and `same-origin` would still hand it the full URL.
    expect($response->headers->get('Referrer-Policy'))->toBe('no-referrer')
        ->and($response->headers->get('Cache-Control'))->toContain('no-store');
});
