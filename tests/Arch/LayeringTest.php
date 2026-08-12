<?php

declare(strict_types=1);

/**
 * The layering contract, enforced rather than documented.
 *
 * Core is pure PHP domain logic: no `Illuminate` imports, no framework helpers, no dependency on the
 * bridge. The only thing keeping that true over time is this file — one convenient
 * `use Illuminate\Support\Str;` inside Core is all it takes to quietly end it, and a reviewer will
 * not catch it.
 *
 * **What this no longer claims.** Core imports `laranail/enumerator` (for translatable enum labels),
 * and that package's own composer requirements include six `illuminate/*` packages. So the
 * *dependency tree* is no longer framework-free even though the *code* still is, and a Symfony or
 * Slim application consuming Core would pull Illuminate in through Composer. The earlier claim that
 * such a bridge could consume Core unchanged is gone; saying so plainly beats leaving a test that
 * passes while the guarantee it implies has quietly lapsed.
 *
 * What is still true, and is what the tests below actually pin:
 *
 *  - Core contains no Illuminate imports and calls no framework helpers, so the whole authorization
 *    decision is testable without a request, a session or a container. That — not portability — is
 *    the payoff, and it is why the suite can carry as many refusal tests as it does.
 *  - The enum labels degrade gracefully with no Laravel present, falling back to their `#[Label]`
 *    attributes. Every touchpoint in enumerator's traits is `function_exists()`-guarded, and the one
 *    that is not (`class_basename()` in `translationSlug()`) is overridden on each of our enums for
 *    exactly this reason.
 */
arch('the Core layer never touches Illuminate')
    ->expect('Simtabi\Laranail\Impersonator\Core')
    ->not->toUse('Illuminate');

arch('the Core layer depends only on PSR interfaces, enumerator and itself')
    ->expect('Simtabi\Laranail\Impersonator\Core')
    ->toOnlyUse([
        'Simtabi\Laranail\Impersonator\Core',
        'Psr\Log',
        'Psr\Clock',
        'Psr\EventDispatcher',

        // Enum labels only — the `#[Label]` attribute plus the two traits that resolve it. This is a
        // closed list on purpose: it is the allowlist that has to grow before anything else from the
        // wider family can reach into Core, which makes that a decision rather than an accident.
        'Simtabi\Laranail\Enumerator\Attributes',
        'Simtabi\Laranail\Enumerator\Concerns',
        'Simtabi\Laranail\Enumerator\Contracts',
    ]);

arch('the Core layer never reaches for a framework helper')
    ->expect([
        'app',
        'auth',
        'config',
        'request',
        'response',
        'session',
        'redirect',
        'route',
        'url',
        'now',
        'event',
        'cache',
        'logger',
        'abort',
        'abort_if',
        'abort_unless',
        'dispatch',
        'report',
        'validator',
        'view',
    ])
    ->not->toBeUsedIn('Simtabi\Laranail\Impersonator\Core');

arch('the Core layer does not depend on the bridge')
    ->expect('Simtabi\Laranail\Impersonator\Laravel')
    ->not->toBeUsedIn('Simtabi\Laranail\Impersonator\Core');

arch('contracts are interfaces')
    ->expect('Simtabi\Laranail\Impersonator\Core\Contracts')
    ->toBeInterfaces();

arch('value objects are immutable')
    ->expect('Simtabi\Laranail\Impersonator\Core\Values')
    ->toBeReadonly();

arch('enums are enums')
    ->expect('Simtabi\Laranail\Impersonator\Core\Enums')
    ->toBeEnums();

arch('nothing is left debugging')
    ->expect(['dd', 'dump', 'ray', 'var_dump', 'print_r', 'die', 'exit'])
    ->not->toBeUsed();

arch('strict types are declared everywhere')
    ->expect('Simtabi\Laranail\Impersonator')
    ->toUseStrictTypes();
