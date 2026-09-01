<?php

declare(strict_types=1);

use Rector\CodeQuality\Rector\Identical\FlipTypeControlToUseExclusiveTypeRector;
use Rector\CodingStyle\Rector\ArrowFunction\ArrowFunctionDelegatingCallToFirstClassCallableRector;
use Rector\Config\RectorConfig;
use Rector\DeadCode\Rector\MethodCall\RemoveNullArgOnNullDefaultParamRector;
use Rector\Set\ValueObject\LevelSetList;

return RectorConfig::configure()
    ->withPaths([
        __DIR__.'/src',
        __DIR__.'/tests',
    ])
    // Pinned to the php84 set, matching the ^8.4.1 floor. The pin is the point rather
    // than the level: it stops anything 8.5-only slipping in from a developer's newer
    // runtime, which CI on 8.5 would happily accept and an 8.4 install would not.
    //
    // Note laranail/package-tools deliberately stays on php83 — its floor is lower. Do
    // not copy this line between the two packages without checking the floor.
    ->withSets([LevelSetList::UP_TO_PHP_84])
    ->withPreparedSets(
        deadCode: true,
        codeQuality: true,
        typeDeclarations: true,
    )
    ->withSkip([
        // Rewrites `$endedAt === null` into `! $endedAt instanceof DateTimeImmutable`.
        // Equivalent, and markedly harder to read on the nullable timestamps that
        // carry this package's whole lifecycle state.
        FlipTypeControlToUseExclusiveTypeRector::class,

        // Collapses `fn () => $this->check()` into a first-class callable. Every
        // entry in the policy's check list has to be a thunk, and converting only
        // the no-argument ones leaves that list in two styles at once — which reads
        // worse than the uniform closures, and is the whole reason the list is
        // legible as a sequence of rules. Also the point of the short-circuit tests,
        // where the closure is what proves later checks never run.
        ArrowFunctionDelegatingCallToFirstClassCallableRector::class,

        // Strips an explicit `null` that matches the parameter default. In these
        // tests the explicit null *is* the case under test — "no redirect was
        // requested", "no max_duration was set" — so removing it deletes the
        // assertion's meaning.
        RemoveNullArgOnNullDefaultParamRector::class => [
            __DIR__.'/tests',
        ],
    ]);
