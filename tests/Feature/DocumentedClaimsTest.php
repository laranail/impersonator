<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\TablesCheck;
use Simtabi\Laranail\Impersonator\Laravel\Support\PackageTables;

/*
| The published documentation, checked against the code.
|
| Every assertion here exists because the claim it pins had already drifted. The doctor gained two checks
| and the docs still said nineteen; the schema gained a fifth table and `installation.md` still listed
| four — and, worse, so did the doctor's own table check, so a missing approval-decisions table was
| reported by nothing at all.
|
| A count in prose is a claim, and an unchecked claim rots. These are cheap; the drift is not.
|
| Note the `str_contains(...)->toBeTrue($message)` shape rather than `toContain($needle, $message)`:
| Pest's `toContain()` takes **variadic needles**, so a failure message passed as a second argument is
| silently asserted as another needle. Four of these tests failed that way before the shape changed.
*/

it('names the right number of doctor checks', function (): void {
    // The count is spelled as a word, so it has to be read as one. An unmapped word fails with the word
    // in the message rather than silently comparing against zero — a count that cannot be parsed is not
    // the same as a count that disagrees, and only one of the two is fixed by editing the doctor.
    $words = [
        'Sixteen' => 16, 'Seventeen' => 17, 'Eighteen' => 18, 'Nineteen' => 19, 'Twenty' => 20,
        'Twenty-one' => 21, 'Twenty-two' => 22, 'Twenty-three' => 23, 'Twenty-four' => 24,
        'Twenty-five' => 25,
    ];

    expect(preg_match(
        '/^(\S+) checks:/m',
        (string) file_get_contents(dirname(__DIR__, 2).'/docs/tools/commands.md'),
        $m,
    ))->toBe(1, 'commands.md no longer states a doctor-check count');

    // `array_key_exists(...)->toBeTrue($message)`, not `toHaveKey($key, $message)`: that second argument
    // is the expected *value*, so the message would be asserted as the count. Exactly the trap the note
    // above records for `toContain()` — the two matchers read alike and neither takes a message.
    expect(array_key_exists($m[1], $words))
        ->toBeTrue("unrecognised count word [{$m[1]}] in commands.md");

    expect($words[$m[1]])->toBe(count(Checks::all()));
});

it('consults the config key for every package table', function (): void {
    // The drift this catches was real: the doctor's existence check listed four tables, the approval-chain
    // work added a fifth, and a missing `impersonator_approval_decisions` was reported by nothing.
    //
    // The list now has one home in PackageTables, so this asserts the two ends that class cannot enforce
    // itself: that the migration creates exactly those tables, and that each doctor check reading the
    // list actually reacts to every entry.
    //
    // Asserted by pointing each key at a table that does not exist, rather than by dropping the real one.
    // Two reasons: no DDL, so it is driver-independent — an earlier version dropped tables and hit
    // PostgreSQL's foreign-key enforcement, which SQLite does not have — and it tests the property that
    // actually matters, which is that a check *reads* every key.
    $map = PackageTables::map();

    $created = array_values(array_filter(
        array_map(
            static fn (mixed $table): string => is_array($table) ? (string) ($table['name'] ?? '') : '',
            Schema::getTables(),
        ),
        static fn (string $name): bool => str_starts_with($name, 'impersonator_'),
    ));

    // A sixth table in the migration with no entry here fails on the count.
    expect($created)->toHaveCount(count($map));

    foreach ($map as $key => $real) {
        expect($created)->toContain($real);

        config()->set('laranail.impersonator.'.$key, 'a_table_that_is_not_there');

        expect(str_contains(app(TablesCheck::class)->run()->message, 'a_table_that_is_not_there'))
            ->toBeTrue("the doctor does not consult [{$key}]");

        config()->set('laranail.impersonator.'.$key, $real);
    }

    // The row-level-security check reads the same list, but reacts by querying `pg_class` rather than by
    // returning a message, and skips entirely off PostgreSQL — so there is no behaviour to observe on
    // every driver. What is asserted instead is that it still *reads the shared list*, because the way
    // this drifted the first time was a second hand-maintained copy, and a copy is visible in the source.
    foreach (['TablesCheck', 'RowLevelSecurityCheck'] as $check) {
        $source = (string) file_get_contents(
            dirname(__DIR__, 2).'/src/Laravel/Doctor/Checks/'.$check.'.php',
        );

        expect(str_contains($source, 'PackageTables::'))
            ->toBeTrue("[{$check}] no longer reads the shared table list")
            ->and(preg_match_all("/'impersonator_[a-z_]+'/", $source))
            ->toBe(0, "[{$check}] has its own copy of the table names again");
    }
});

it('lists every table the migration creates in the install docs', function (): void {
    $docs = (string) file_get_contents(dirname(__DIR__, 2).'/docs/installation.md');

    foreach (Schema::getTables() as $table) {
        $name = is_array($table) ? (string) ($table['name'] ?? '') : '';

        if (str_starts_with($name, 'impersonator_')) {
            expect(str_contains($docs, $name))
                ->toBeTrue("installation.md does not list [{$name}]");
        }
    }
});

it('names the right number of artisan commands', function (): void {
    $commands = glob(dirname(__DIR__, 2).'/src/Laravel/Commands/*Command.php') ?: [];
    $docs = (string) file_get_contents(dirname(__DIR__, 2).'/docs/tools/commands.md');

    expect($commands)->toHaveCount(7)
        ->and($docs)->toContain('Seven Artisan commands');

    // And each one is actually reachable by the name the docs give it.
    foreach ($commands as $file) {
        $signature = strtolower(preg_replace('/([a-z])([A-Z])/', '$1-$2', basename($file, 'Command.php')) ?? '');

        expect(str_contains($docs, 'laranail::impersonator.'.$signature))
            ->toBeTrue("undocumented command [{$signature}]");
    }
});

it('names the right number of events', function (): void {
    $events = glob(dirname(__DIR__, 2).'/src/Core/Events/*.php') ?: [];

    expect($events)->toHaveCount(15)
        ->and((string) file_get_contents(dirname(__DIR__, 2).'/docs/tools/events.md'))
        ->toContain('Fifteen events');
});

it('documents every middleware alias it registers', function (): void {
    // An alias nobody documents is an alias nobody uses, and one documented but not registered is a
    // broken instruction.
    $provider = (string) file_get_contents(
        dirname(__DIR__, 2).'/src/Laravel/Providers/ImpersonatorServiceProvider.php',
    );

    preg_match_all("/aliasMiddleware\('([a-z.-]+)'/", $provider, $matches);

    $docs = '';

    foreach (['docs', 'config'] as $dir) {
        foreach (glob(dirname(__DIR__, 2).'/'.$dir.'/**/*.{md,php}', GLOB_BRACE) ?: [] as $file) {
            $docs .= (string) file_get_contents($file);
        }

        foreach (glob(dirname(__DIR__, 2).'/'.$dir.'/*.{md,php}', GLOB_BRACE) ?: [] as $file) {
            $docs .= (string) file_get_contents($file);
        }
    }

    expect($matches[1])->not->toBeEmpty();

    foreach ($matches[1] as $alias) {
        expect(str_contains($docs, $alias))->toBeTrue("undocumented middleware alias [{$alias}]");
    }
});

it('documents every publish tag it registers', function (): void {
    $provider = (string) file_get_contents(
        dirname(__DIR__, 2).'/src/Laravel/Providers/ImpersonatorServiceProvider.php',
    );

    preg_match_all("/'(impersonator-[a-z]+)'\)/", $provider, $matches);

    $docs = (string) file_get_contents(dirname(__DIR__, 2).'/docs/installation.md');

    expect(array_unique($matches[1]))->toHaveCount(4);

    foreach (array_unique($matches[1]) as $tag) {
        expect(str_contains($docs, $tag))->toBeTrue("undocumented publish tag [{$tag}]");
    }
});

it('splices no hand-rolled plurals into user-facing text', function (): void {
    // `1 minute(s)` is wrong even in English, and in a language whose plural rules are not English's the
    // suffix is not merely ugly — it is meaningless. Two commands reached a release with none of their
    // output translated at all, which is how four of these survived the localisation pass; a grep is the
    // only thing that notices, because every one of them renders without error.
    //
    // Scanned as PHP *string tokens* rather than as lines. Prose about the pattern has to stay legal —
    // `MessageCatalog` documents the rule and cannot do that without naming it — and a line-based scan
    // with a comment-prefix skiplist got that wrong twice: it missed a `|`-prefixed line inside a block
    // comment, and it needed a hand-maintained exception per file that discussed the subject. The
    // tokeniser knows what a comment is.
    $offenders = [];

    foreach (['src', 'resources/lang'] as $dir) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(dirname(__DIR__, 2).'/'.$dir),
        );

        foreach ($files as $file) {
            if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            $tokens = token_get_all((string) file_get_contents($file->getPathname()));

            foreach ($tokens as $token) {
                if (! is_array($token)) {
                    continue;
                }

                [$id, $text, $line] = $token;

                $isString = in_array($id, [
                    T_CONSTANT_ENCAPSED_STRING,
                    T_ENCAPSED_AND_WHITESPACE,
                    T_INLINE_HTML,
                ], true);

                if ($isString && str_contains($text, '(s)')) {
                    $offenders[] = $file->getFilename().':'.$line;
                }
            }
        }
    }

    expect($offenders)->toBe([], 'hand-rolled plural at '.implode(', ', $offenders));
});

it('translates the output of every command', function (): void {
    // Both gaps this catches were real: `export-audit` and `scrub-identity` were added after the
    // localisation pass and shipped entirely in English, against a documented claim that console output
    // is translated. A command with no `__()` at all is the shape that slips through review.
    foreach (glob(dirname(__DIR__, 2).'/src/Laravel/Commands/*Command.php') ?: [] as $file) {
        $source = (string) file_get_contents($file);

        expect(preg_match('/__\(|trans_choice\(/', $source))
            ->toBe(1, 'no translated output in '.basename($file));
    }
});

it('names every published language file in the install docs', function (): void {
    // The docs both count these files and tabulate them, so a new one drifts two claims at once — and a
    // translator reading the table is the person who finds out.
    $files = array_map(
        static fn (string $path): string => basename($path),
        glob(dirname(__DIR__, 2).'/resources/lang/en/*.php') ?: [],
    );

    $docs = (string) file_get_contents(dirname(__DIR__, 2).'/docs/installation.md');

    expect($files)->toHaveCount(8)
        ->and($docs)->toContain('Eight files land');

    foreach ($files as $file) {
        expect(str_contains($docs, '`'.$file.'`'))
            ->toBeTrue("installation.md does not list [{$file}]");
    }
});

it('names the right number of adapters, drivers, modes and singletons', function (): void {
    // The remaining counted claims, in one test because they share a failure mode: each is a directory
    // whose size is quoted in prose, and adding a file to one of them is the least likely moment for
    // anybody to reread the docs.
    $claims = [
        ['src/Laravel/Adapters/*.php', 'docs/tools/auth-adapters.md', 'Four adapters', 4],
        ['src/Laravel/Drivers/*.php', 'docs/tools/drivers.md', 'Three drivers', 3],
        ['src/Laravel/Modes/*.php', 'docs/tools/modes.md', 'Three modes', 3],
    ];

    foreach ($claims as [$glob, $doc, $phrase, $expected]) {
        $files = glob(dirname(__DIR__, 2).'/'.$glob) ?: [];

        expect($files)->toHaveCount($expected, "wrong file count for [{$glob}]");

        expect(str_contains((string) file_get_contents(dirname(__DIR__, 2).'/'.$doc), $phrase))
            ->toBeTrue("[{$doc}] no longer says [{$phrase}]");
    }

    // The Octane reset story turns on this number — the docs explain which singletons may hold request
    // state and why the rest must not be reset, so the total is load-bearing rather than decorative.
    $provider = (string) file_get_contents(
        dirname(__DIR__, 2).'/src/Laravel/Providers/ImpersonatorServiceProvider.php',
    );

    expect(preg_match_all('/singleton\(/', $provider))->toBe(17)
        ->and((string) file_get_contents(dirname(__DIR__, 2).'/docs/security.md'))
        ->toContain('seventeen singletons');
});
