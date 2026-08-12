<?php

declare(strict_types=1);

/**
 * The layering contract, enforced rather than documented.
 *
 * "Framework agnostic" means something specific here: the Core namespace is
 * pure PHP domain logic that a Symfony or Slim bridge could consume unchanged,
 * shipped as a Laravel package today. The only thing keeping that true over
 * time is this file — one convenient `use Illuminate\Support\Str;` inside Core
 * is all it takes to quietly end it, and a reviewer will not catch it.
 */
arch('the Core layer never touches Illuminate')
    ->expect('Simtabi\Laranail\Impersonator\Core')
    ->not->toUse('Illuminate');

arch('the Core layer depends only on PSR interfaces and itself')
    ->expect('Simtabi\Laranail\Impersonator\Core')
    ->toOnlyUse([
        'Simtabi\Laranail\Impersonator\Core',
        'Psr\Log',
        'Psr\Clock',
        'Psr\EventDispatcher',
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
