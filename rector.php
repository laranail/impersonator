<?php

declare(strict_types=1);

use Rector\CodeQuality\Rector\Identical\FlipTypeControlToUseExclusiveTypeRector;
use Rector\CodingStyle\Rector\ArrowFunction\ArrowFunctionDelegatingCallToFirstClassCallableRector;
use Rector\Config\RectorConfig;
use Rector\DeadCode\Rector\MethodCall\RemoveNullArgOnNullDefaultParamRector;
use Rector\Set\ValueObject\LevelSetList;

return RectorConfig::configure()
    ->withPaths([
        __DIR__ . '/src',
        __DIR__ . '/tests',
    ])
    // Pinned to the php83 set: the package floor is PHP ^8.3, so nothing may
    // introduce 8.4-only syntax even though CI also runs 8.4 and 8.5.
    ->withSets([LevelSetList::UP_TO_PHP_83])
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
            __DIR__ . '/tests',
        ],
    ]);
