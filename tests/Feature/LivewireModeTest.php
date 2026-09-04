<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;
use Simtabi\Laranail\Impersonator\Laravel\Support\LivewireAction;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\EnforceImpersonationMode;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;

/*
| `limited` mode under Livewire.
|
| The gap this closes: every Livewire action POSTs to one endpoint with the component and method in the
| payload, so `deny_routes`, `deny_paths` and `allowed_methods` see one route, one path and one method
| for every action in the application. A rule naming `password.update` matched nothing, and a rule broad
| enough to match blocked everything — so `limited` was substantially weaker under Livewire than it read.
|
| Livewire is deliberately **not** a dependency, so these drive the documented payload shapes directly.
| That is a real limitation of this coverage and worth naming: it proves the parsing and the matching,
| not that a given Livewire release still sends this shape.
*/

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('laranail.impersonator.limits.state_cache.ttl', 0);
    config()->set('laranail.impersonator.modes.limited.deny_models', []);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);

    // Stands in for Livewire's own endpoint. The package matches on the payload, not on who registered
    // the route, so this is faithful to what it actually inspects.
    Route::middleware(['web', EnforceImpersonationMode::class])
        ->post('/livewire/update', fn (): string => 'ok');
    Route::middleware(['web', EnforceImpersonationMode::class])
        ->post('/livewire/message/{component}', fn (): string => 'ok');
});

/** A Livewire 3 update payload: the component name is inside a JSON-encoded snapshot string. */
function livewireV3(string $component, string $method): array
{
    return [
        'components' => [[
            'snapshot' => json_encode(['data' => [], 'memo' => ['id' => 'abc123', 'name' => $component]]),
            'updates'  => [],
            'calls'    => [['path' => '', 'method' => $method, 'params' => []]],
        ]],
    ];
}

it('denies a Livewire action by component and method', function (): void {
    config()->set('laranail.impersonator.modes.limited.deny_livewire', ['ProfileForm::updatePassword']);

    Impersonator::enter($this->target, mode: 'limited');

    $this->postJson('/livewire/update', livewireV3('ProfileForm', 'updatePassword'))->assertForbidden();

    // A different method on the same component is untouched — the axis is precise, not a blanket.
    $this->postJson('/livewire/update', livewireV3('ProfileForm', 'save'))->assertOk();
});

it('matches a whole component with a wildcard', function (): void {
    config()->set('laranail.impersonator.modes.limited.deny_livewire', ['BillingPanel::*']);

    Impersonator::enter($this->target, mode: 'limited');

    $this->postJson('/livewire/update', livewireV3('BillingPanel', 'anything'))->assertForbidden();
    $this->postJson('/livewire/update', livewireV3('ProfileForm', 'anything'))->assertOk();
});

it('matches a method wherever it appears', function (): void {
    config()->set('laranail.impersonator.modes.limited.deny_livewire', ['*::destroy']);

    Impersonator::enter($this->target, mode: 'limited');

    $this->postJson('/livewire/update', livewireV3('ProfileForm', 'destroy'))->assertForbidden();
    $this->postJson('/livewire/update', livewireV3('BillingPanel', 'destroy'))->assertForbidden();
    $this->postJson('/livewire/update', livewireV3('BillingPanel', 'refresh'))->assertOk();
});

it('reads a Livewire 2 payload as well', function (): void {
    // Both shapes are in the wild, and a package that only handled the newer one would silently enforce
    // nothing on the older — which is the failure mode this whole axis exists to remove.
    config()->set('laranail.impersonator.modes.limited.deny_livewire', ['profile-form::updatePassword']);

    Impersonator::enter($this->target, mode: 'limited');

    $this->postJson('/livewire/message/profile-form', [
        'updates' => [['type' => 'callMethod', 'payload' => ['method' => 'updatePassword', 'params' => []]]],
    ])->assertForbidden();

    $this->postJson('/livewire/message/profile-form', [
        'updates' => [['type' => 'callMethod', 'payload' => ['method' => 'save', 'params' => []]]],
    ])->assertOk();
});

it('denies every call in a batched payload, not just the first', function (): void {
    // Livewire batches: one request can call several methods across several components. Checking only
    // the first would let a denied action ride along behind an allowed one.
    config()->set('laranail.impersonator.modes.limited.deny_livewire', ['*::destroy']);

    Impersonator::enter($this->target, mode: 'limited');

    $this->postJson('/livewire/update', [
        'components' => [
            [
                'snapshot' => json_encode(['memo' => ['name' => 'ProfileForm']]),
                'calls'    => [['method' => 'save'], ['method' => 'destroy']],
            ],
        ],
    ])->assertForbidden();
});

it('costs nothing when no Livewire rule is configured', function (): void {
    // The payload is not parsed at all unless the mode has rules for it: decoding a JSON body to
    // discover it was not Livewire is a cost every application would otherwise pay.
    config()->set('laranail.impersonator.modes.limited.deny_livewire', []);

    Impersonator::enter($this->target, mode: 'limited');

    $this->postJson('/livewire/update', livewireV3('ProfileForm', 'updatePassword'))->assertOk();
});

it('allows an unparseable payload rather than guessing', function (): void {
    // An empty identifier list means the axis does not match — never that the request is allowed by
    // fiat. The other axes still apply, and read_only is unaffected because its guard is at the
    // persistence layer.
    config()->set('laranail.impersonator.modes.limited.deny_livewire', ['*::destroy']);

    Impersonator::enter($this->target, mode: 'limited');

    foreach ([
        ['components' => 'not-an-array'],
        ['components' => [['snapshot' => 'not json', 'calls' => [['method' => 'save']]]]],
        ['components' => [[]]],
        [],
    ] as $payload) {
        $this->postJson('/livewire/update', $payload)->assertOk();
    }
});

it('reads identifiers without a booted mode, for a host to inspect', function (): void {
    $request = Request::create('/livewire/update', 'POST', livewireV3('ProfileForm', 'save'));

    expect(LivewireAction::identifiersFrom($request))
        ->toContain('ProfileForm', 'save', 'ProfileForm::save');

    // Not a Livewire path, so nothing is claimed about it.
    expect(LivewireAction::identifiersFrom(Request::create('/app/page', 'POST')))->toBe([]);
});

it('leaves read_only unaffected, since its guard is below the http layer', function (): void {
    // Stated in the docs and worth pinning: read_only refuses the write itself, so it never depended on
    // recognising the route in the first place.
    config()->set('laranail.impersonator.modes.read_only.prevent_writes', true);

    Impersonator::enter($this->target, mode: 'read_only');

    $this->postJson('/livewire/update', livewireV3('ProfileForm', 'save'))->assertForbidden();
});
