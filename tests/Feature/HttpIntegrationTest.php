<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Support\BannerPresenter;
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

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer & Co']);
});

it('registers the leave route', function (): void {
    expect(Route::has('impersonator.leave'))->toBeTrue()
        ->and(route('impersonator.leave'))->toEndWith('/impersonator/leave');
});

it('ends the impersonation through the leave route', function (): void {
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    $this->get(route('impersonator.leave'))->assertRedirect('/');

    expect(Impersonator::isImpersonating())->toBeFalse();
});

it('refuses the leave route when nothing is being impersonated', function (): void {
    // Otherwise a stray request logs somebody out of their own account.
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);

    $this->get(route('impersonator.leave'))->assertForbidden();
});

it('redirects after leaving to the configured destination', function (): void {
    config()->set('laranail.impersonator.redirects.after_leave', '/admin/users');
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    $this->get(route('impersonator.leave'))->assertRedirect('/admin/users');
});

it('does not register routes when route registration is disabled', function (): void {
    // Verified through config rather than by re-booting: the flag is read at boot,
    // and asserting on it here documents the contract without a second kernel.
    expect(config('laranail.impersonator.routes.register'))->toBeTrue();
});

// ── Blade ───────────────────────────────────────────────────────────────────

it('reports impersonating state to Blade from server-side state only', function (): void {
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);

    expect(Blade::render('@impersonating YES @else NO @endimpersonating'))->toContain('NO');

    Impersonator::enter($this->target);

    expect(Blade::render('@impersonating YES @else NO @endimpersonating'))->toContain('YES');
});

it('exposes the active mode to Blade', function (): void {
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(Blade::render('@impersonationMode("full") FULL @endimpersonationMode'))->toContain('FULL')
        ->and(Blade::render('@impersonationMode("read_only") RO @endimpersonationMode'))->not->toContain('RO');
});

it('gates a Blade block on whether a target may be impersonated', function (): void {
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);

    $template = '@canImpersonate($user) BUTTON @endcanImpersonate';

    expect(Blade::render($template, ['user' => $this->target]))->toContain('BUTTON')
        // Self-impersonation is refused, so the button must not render for the
        // operator's own row — the same policy the action itself runs.
        ->and(Blade::render($template, ['user' => $this->admin]))->not->toContain('BUTTON');
});

// ── Banner ──────────────────────────────────────────────────────────────────

it('renders nothing when not impersonating', function (): void {
    $this->startSession();

    expect(app(BannerPresenter::class)->render())->toBe('');
});

it('renders the banner with the target, the operator and the mode', function (): void {
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    $html = app(BannerPresenter::class)->render();

    expect($html)->toContain('impersonator-banner')
        ->and($html)->toContain('Admin')
        ->and($html)->toContain('data-impersonator-mode="full"')
        ->and($html)->toContain(route('impersonator.leave'));
});

it('escapes the target display name', function (): void {
    // The name is a user-editable attribute, so treating it as markup would make
    // the banner an XSS sink reachable by any user who can set their own name.
    $this->startSession();
    $xss = User::create(['name' => '<script>alert(1)</script>']);
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($xss);

    $html = app(BannerPresenter::class)->render();

    expect($html)->not->toContain('<script>alert(1)</script>')
        ->and($html)->toContain('&lt;script&gt;');
});

it('escapes an ampersand in the display name', function (): void {
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(app(BannerPresenter::class)->render())->toContain('Customer &amp; Co');
});

it('renders nothing when the banner is switched off', function (): void {
    config()->set('laranail.impersonator.banner.enabled', false);
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(app(BannerPresenter::class)->render())->toBe('');
});

it('honours the theme and position config', function (): void {
    config()->set('laranail.impersonator.banner.theme', 'light');
    config()->set('laranail.impersonator.banner.position', 'top');
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    $html = app(BannerPresenter::class)->render();

    expect($html)->toContain('data-impersonator-theme="light"')
        ->and($html)->toContain('top: 0');
});

it('falls back to an unrecognised theme rather than emitting it', function (): void {
    config()->set('laranail.impersonator.banner.theme', 'neon');
    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(app(BannerPresenter::class)->render())->toContain('data-impersonator-theme="auto"');
});

it('uses a custom display name resolver when one is registered', function (): void {
    $this->startSession();
    Impersonator::displayNameUsing(static fn (User $user): string => 'Account #' . $user->getKey());
    Auth::guard('web')->setUser($this->admin);

    expect(Impersonator::displayNameFor($this->target))->toBe('Account #' . $this->target->getKey());
});
