<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;
use Simtabi\Laranail\Impersonator\Laravel\Support\BannerPresenter;
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
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 5);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer & Co']);

    $this->startSession();
});

// ── banner ──────────────────────────────────────────────────────────────────

it('renders the banner component only while impersonating', function (): void {
    // The property that lets a host drop it once into a layout and never wrap it in
    // a conditional — and a forgotten conditional is a banner that silently fails.
    Auth::guard('web')->setUser($this->admin);

    expect(trim(Blade::render('<x-laranail-impersonator::banner />')))->toBe('');

    Impersonator::enter($this->target);

    expect(Blade::render('<x-laranail-impersonator::banner />'))->toContain('impersonator-banner');
});

it('lets a banner attribute override config per placement', function (): void {
    config()->set('laranail.impersonator.banner.position', 'bottom');
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(Blade::render('<x-laranail-impersonator::banner position="top" theme="light" />'))
        ->toContain('top: 0')
        ->toContain('data-impersonator-theme="light"');
});

it('is also reachable under the namespaced form', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(Blade::render('<x-laranail-impersonator::impersonation-banner />'))->toContain('impersonator-banner');
});

// ── impersonate button ──────────────────────────────────────────────────────

it('renders a POST form for an allowed target', function (): void {
    // Entering changes state, so it must not be a GET a crawler or a pasted URL can
    // trigger.
    Auth::guard('web')->setUser($this->admin);

    $html = Blade::render('<x-laranail-impersonator::impersonate-button :user="$user" />', ['user' => $this->target]);

    expect($html)->toContain('method="POST"')
        ->toContain(route('laranail-impersonator.enter'))
        ->toContain('name="target_type" value="user"')
        ->toContain('name="target_id" value="' . $this->target->getKey() . '"')
        ->toContain('_token');
});

it('renders nothing when the policy would refuse', function (): void {
    // Same policy the endpoint runs, so a visible button and a 403 cannot disagree.
    Auth::guard('web')->setUser($this->admin);

    expect(trim(Blade::render('<x-laranail-impersonator::impersonate-button :user="$user" />', ['user' => $this->admin])))
        ->toBe('');
});

it('renders nothing without a user', function (): void {
    expect(trim(Blade::render('<x-laranail-impersonator::impersonate-button />')))->toBe('');
});

it('prompts for a reason when one is required', function (): void {
    // Otherwise the operator discovers the requirement through a rejection.
    config()->set('laranail.impersonator.reason.require', true);
    Auth::guard('web')->setUser($this->admin);

    expect(Blade::render('<x-laranail-impersonator::impersonate-button :user="$user" />', ['user' => $this->target]))
        ->toContain('name="reason"')
        ->toContain('required');
});

it('forwards its attribute bag so host styles apply', function (): void {
    Auth::guard('web')->setUser($this->admin);

    expect(Blade::render('<x-laranail-impersonator::impersonate-button :user="$user" class="btn btn-sm" />', ['user' => $this->target]))
        ->toContain('btn btn-sm');
});

it('escapes the display name in a confirmation prompt', function (): void {
    Auth::guard('web')->setUser($this->admin);
    $xss = User::create(['name' => '"><script>alert(1)</script>']);

    $html = Blade::render('<x-laranail-impersonator::impersonate-button :user="$user" confirm />', ['user' => $xss]);

    expect($html)->not->toContain('<script>alert(1)</script>');
});

// ── leave button, badge, guard ───────────────────────────────────────────────

it('renders the leave button only while impersonating', function (): void {
    Auth::guard('web')->setUser($this->admin);

    expect(trim(Blade::render('<x-laranail-impersonator::leave-button />')))->toBe('');

    Impersonator::enter($this->target);

    expect(Blade::render('<x-laranail-impersonator::leave-button />'))
        ->toContain(route('laranail-impersonator.leave'))
        ->toContain('Stop impersonating');
});

it('renders the mode badge while impersonating', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target, mode: 'read_only');

    expect(Blade::render('<x-laranail-impersonator::badge />'))
        // The raw mode stays available as a data attribute, for styling and for a host's own scripting.
        ->toContain('data-impersonator-mode="read_only"')
        // The visible text is a translated label, not the config key with its underscore removed.
        // It was `read only`; `str_replace('_', ' ', $mode)` is a value, not a label.
        ->toContain('Read only');
});

it('resolves component labels at render time and lets a tag override them', function (): void {
    // A promoted-property default must be a constant expression, so these could not be `__()`. Null
    // now means "use the shipped label" — and an explicit attribute still has to win, or an
    // application that customised its button copy would silently lose it.
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    app('translator')->addLines(['components.leave' => 'Quitter'], 'en', 'laranail-impersonator');

    expect(Blade::render('<x-laranail-impersonator::leave-button />'))->toContain('Quitter')
        ->and(Blade::render('<x-laranail-impersonator::leave-button label="Back to admin" />'))
        ->toContain('Back to admin')
        ->and(Blade::render('<x-laranail-impersonator::leave-button label="Back to admin" />'))
        ->not->toContain('Quitter');
});

it('labels a mode nobody registered a line for', function (): void {
    // Modes are user-registrable, so an unknown one has to degrade to the humanised form rather than
    // rendering blank. Capitalised, because it is being used as a label.
    expect(app(BannerPresenter::class)->modeName('finance_only'))->toBe('Finance only')
        ->and(app(BannerPresenter::class)->modeName('read_only'))->toBe('Read only')
        ->and(app(BannerPresenter::class)->modeName('read_only', short: true))->toBe('Read only');
});

it('escapes the target name in the badge', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    expect(Blade::render('<x-laranail-impersonator::badge show-target />'))->toContain('Customer &amp; Co');
});

it('renders a guarded slot only while impersonating', function (): void {
    Auth::guard('web')->setUser($this->admin);

    $template = '<x-laranail-impersonator::when-impersonating>INSIDE</x-laranail-impersonator::when-impersonating>';

    expect(Blade::render($template))->not->toContain('INSIDE');

    Impersonator::enter($this->target);

    expect(Blade::render($template))->toContain('INSIDE');
});

it('scopes a guarded slot to a mode', function (): void {
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target, mode: 'read_only');

    expect(Blade::render('<x-laranail-impersonator::when-impersonating mode="read_only">RO</x-laranail-impersonator::when-impersonating>'))
        ->toContain('RO');

    expect(Blade::render('<x-laranail-impersonator::when-impersonating mode="full">FULL</x-laranail-impersonator::when-impersonating>'))
        ->not->toContain('FULL');
});

it('inverts a guarded slot with unless', function (): void {
    Auth::guard('web')->setUser($this->admin);

    expect(Blade::render('<x-laranail-impersonator::when-impersonating unless>NORMAL</x-laranail-impersonator::when-impersonating>'))
        ->toContain('NORMAL');

    Impersonator::enter($this->target);

    expect(Blade::render('<x-laranail-impersonator::when-impersonating unless>NORMAL</x-laranail-impersonator::when-impersonating>'))
        ->not->toContain('NORMAL');
});

it('renders every component under its scoped, class-derived and deprecated bare names', function (): void {
    // The class-derived form resolves by *class* name, so it is not always the same string as the
    // scoped alias -- `LeaveImpersonationButton` is `leave-button` scoped. The bare tag is the
    // deprecated pre-0.1 spelling and must still render the same thing. This pins the table in
    // docs/tools/blade-components.md, which is otherwise easy to get wrong.
    Auth::guard('web')->setUser($this->admin);
    Impersonator::enter($this->target);

    $spellings = [
        '<x-laranail-impersonator::banner />' => [
            '<x-laranail-impersonator::impersonation-banner />',
            '<x-impersonation-banner />',
        ],
        '<x-laranail-impersonator::badge />' => [
            '<x-laranail-impersonator::impersonation-badge />',
            '<x-impersonation-badge />',
        ],
        '<x-laranail-impersonator::leave-button />' => [
            '<x-laranail-impersonator::leave-impersonation-button />',
            '<x-impersonation-leave-button />',
        ],
    ];

    foreach ($spellings as $scoped => $others) {
        expect(Blade::render($scoped))->not->toBe('');

        foreach ($others as $other) {
            expect(Blade::render($other))->toBe(Blade::render($scoped));
        }
    }

    expect(Blade::render('<x-when-impersonating>YES</x-when-impersonating>'))->toContain('YES')
        ->and(Blade::render('<x-laranail-impersonator::when-impersonating>YES</x-laranail-impersonator::when-impersonating>'))
        ->toContain('YES');
});

it('renders the impersonate button under its scoped and deprecated bare names', function (): void {
    // Rendered while not impersonating, since the button hides itself inside an impersonation.
    Auth::guard('web')->setUser($this->admin);

    $scoped = Blade::render('<x-laranail-impersonator::impersonate-button :user="$user" />', ['user' => $this->target]);
    $bare = Blade::render('<x-impersonate-button :user="$user" />', ['user' => $this->target]);

    expect($scoped)->not->toBe('')
        ->and($bare)->toBe($scoped);
});
