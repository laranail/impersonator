<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('impersonator.limits.max_active_per_impersonator', 5);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer & Co']);

    $this->startSession();
});

// ── banner ──────────────────────────────────────────────────────────────────

it('renders the banner component only while impersonating', function (): void {
    // The property that lets a host drop it once into a layout and never wrap it in
    // a conditional — and a forgotten conditional is a banner that silently fails.
    Auth::guard('web')->setUser($this->admin);

    expect(trim(Blade::render('<x-impersonation-banner />')))->toBe('');

    Impersonator::enter($this->target);

    expect(Blade::render('<x-impersonation-banner />'))->toContain('impersonator-banner');
});

it('lets a banner attribute override config per placement', function (): void {
    config()->set('impersonator.banner.position', 'bottom');
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(Blade::render('<x-impersonation-banner position="top" theme="light" />'))
        ->toContain('top: 0')
        ->toContain('data-impersonator-theme="light"');
});

it('is also reachable under the namespaced form', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(Blade::render('<x-impersonator::impersonation-banner />'))->toContain('impersonator-banner');
});

// ── impersonate button ──────────────────────────────────────────────────────

it('renders a POST form for an allowed target', function (): void {
    // Entering changes state, so it must not be a GET a crawler or a pasted URL can
    // trigger.
    Auth::guard('web')->setUser($this->admin);

    $html = Blade::render('<x-impersonate-button :user="$user" />', ['user' => $this->target]);

    expect($html)->toContain('method="POST"')
        ->toContain(route('impersonator.enter'))
        ->toContain('name="target_type" value="user"')
        ->toContain('name="target_id" value="' . $this->target->getKey() . '"')
        ->toContain('_token');
});

it('renders nothing when the policy would refuse', function (): void {
    // Same policy the endpoint runs, so a visible button and a 403 cannot disagree.
    Auth::guard('web')->setUser($this->admin);

    expect(trim(Blade::render('<x-impersonate-button :user="$user" />', ['user' => $this->admin])))
        ->toBe('');
});

it('renders nothing without a user', function (): void {
    expect(trim(Blade::render('<x-impersonate-button />')))->toBe('');
});

it('prompts for a reason when one is required', function (): void {
    // Otherwise the operator discovers the requirement through a rejection.
    config()->set('impersonator.reason.require', true);
    Auth::guard('web')->setUser($this->admin);

    expect(Blade::render('<x-impersonate-button :user="$user" />', ['user' => $this->target]))
        ->toContain('name="reason"')
        ->toContain('required');
});

it('forwards its attribute bag so host styles apply', function (): void {
    Auth::guard('web')->setUser($this->admin);

    expect(Blade::render('<x-impersonate-button :user="$user" class="btn btn-sm" />', ['user' => $this->target]))
        ->toContain('btn btn-sm');
});

it('escapes the display name in a confirmation prompt', function (): void {
    Auth::guard('web')->setUser($this->admin);
    $xss = User::create(['name' => '"><script>alert(1)</script>']);

    $html = Blade::render('<x-impersonate-button :user="$user" confirm />', ['user' => $xss]);

    expect($html)->not->toContain('<script>alert(1)</script>');
});

// ── leave button, badge, guard ───────────────────────────────────────────────

it('renders the leave button only while impersonating', function (): void {
    Auth::guard('web')->setUser($this->admin);

    expect(trim(Blade::render('<x-impersonation-leave-button />')))->toBe('');

    Impersonator::enter($this->target);

    expect(Blade::render('<x-impersonation-leave-button />'))
        ->toContain(route('impersonator.leave'))
        ->toContain('Stop impersonating');
});

it('renders the mode badge while impersonating', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target, mode: 'read_only');

    expect(Blade::render('<x-impersonation-badge />'))
        ->toContain('data-impersonator-mode="read_only"')
        ->toContain('read only');
});

it('escapes the target name in the badge', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(Blade::render('<x-impersonation-badge show-target />'))->toContain('Customer &amp; Co');
});

it('renders a guarded slot only while impersonating', function (): void {
    Auth::guard('web')->setUser($this->admin);

    $template = '<x-when-impersonating>INSIDE</x-when-impersonating>';

    expect(Blade::render($template))->not->toContain('INSIDE');

    Impersonator::enter($this->target);

    expect(Blade::render($template))->toContain('INSIDE');
});

it('scopes a guarded slot to a mode', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target, mode: 'read_only');

    expect(Blade::render('<x-when-impersonating mode="read_only">RO</x-when-impersonating>'))
        ->toContain('RO');

    expect(Blade::render('<x-when-impersonating mode="full">FULL</x-when-impersonating>'))
        ->not->toContain('FULL');
});

it('inverts a guarded slot with unless', function (): void {
    Auth::guard('web')->setUser($this->admin);

    expect(Blade::render('<x-when-impersonating unless>NORMAL</x-when-impersonating>'))
        ->toContain('NORMAL');

    Impersonator::enter($this->target);

    expect(Blade::render('<x-when-impersonating unless>NORMAL</x-when-impersonating>'))
        ->not->toContain('NORMAL');
});

it('renders every component under both its alias and its namespaced name', function (): void {
    // The namespaced form resolves by *class* name, so it is not always the same string as the
    // alias — `LeaveImpersonationButton` is registered as `impersonation-leave-button`. This pins
    // the table in docs/tools/blade-components.md, which is otherwise easy to get wrong.
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    $pairs = [
        '<x-impersonation-banner />' => '<x-impersonator::impersonation-banner />',
        '<x-impersonation-badge />' => '<x-impersonator::impersonation-badge />',
        '<x-impersonation-leave-button />' => '<x-impersonator::leave-impersonation-button />',
    ];

    foreach ($pairs as $alias => $namespaced) {
        expect(Blade::render($alias))->not->toBe('')
            ->and(Blade::render($namespaced))->toBe(Blade::render($alias));
    }

    expect(Blade::render('<x-impersonator::when-impersonating>YES</x-impersonator::when-impersonating>'))
        ->toContain('YES');
});

it('renders the impersonate button under both names', function (): void {
    // Rendered while not impersonating, since the button hides itself inside an impersonation.
    Auth::guard('web')->setUser($this->admin);

    $alias = Blade::render('<x-impersonate-button :user="$user" />', ['user' => $this->target]);
    $namespaced = Blade::render('<x-impersonator::impersonate-button :user="$user" />', ['user' => $this->target]);

    expect($alias)->not->toBe('')
        ->and($namespaced)->toBe($alias);
});
