<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Lang;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;
use Simtabi\Laranail\Impersonator\Core\Values\Guards;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Values\Mode;
use Simtabi\Laranail\Impersonator\Laravel\Notifications\TargetAccountAccessed;
use Simtabi\Laranail\Impersonator\Laravel\Support\MessageCatalog;

/*
| Localisation, at the render seam.
|
| Core stays framework-free: it builds a stable code plus an English literal, and MessageCatalog swaps
| the literal for a translation when one exists. Two properties this file defends above all:
|
|  - **the code never moves** — it is what an API consumer branches on;
|  - **a missing key degrades to English**, never to a blank or a raw `laranail-impersonator::…` string in
|    somebody's browser.
*/

function catalog(): MessageCatalog
{
    return app(MessageCatalog::class);
}

it('translates a refusal while leaving its code alone', function (): void {
    app('translator')->addLines(['decisions.target_busy' => 'Quelqu\'un d\'autre utilise ce compte.'], 'en', 'laranail-impersonator');

    $decision = Decision::deny(Decision::TARGET_BUSY, 'Somebody else is already impersonating that account.');

    expect(catalog()->forDecision($decision))->toBe('Quelqu\'un d\'autre utilise ce compte.')
        ->and($decision->code)->toBe('target_busy');
});

it('falls back to the English literal when no key exists', function (): void {
    // The property that makes this safe to adopt one key at a time.
    $decision = Decision::deny('a_code_nobody_translated', 'The original sentence.');

    expect(catalog()->forDecision($decision))->toBe('The original sentence.');
});

it('never renders a raw translation key', function (): void {
    // Laravel's translator returns the key when it finds nothing, so a missing key without the
    // `has()` guard shows `laranail-impersonator::decisions.x` to a user — worse than the English it replaced.
    foreach (['target_busy', 'nonexistent_code', 'session_terminated'] as $code) {
        $message = catalog()->forDecision(Decision::deny($code, 'Fallback sentence.'));

        expect($message)->not->toContain('laranail-impersonator::')
            ->and($message)->not->toBe($code);
    }
});

it('tells apart two sentences that share one code', function (): void {
    // The finding that shaped the cascade: a code is not a unique message identifier. Three
    // sentences share `session_terminated`, so keying on the code alone would tell an operator whose
    // session an administrator killed that it had merely expired.
    $revoked = Decision::deny(Decision::SESSION_TERMINATED, 'x', ['detail' => 'revoked']);
    $expired = Decision::deny(Decision::SESSION_TERMINATED, 'x', ['detail' => 'expired']);

    expect(catalog()->forDecision($revoked))->toBe('This impersonation was ended by an administrator.')
        ->and(catalog()->forDecision($expired))->toBe('This impersonation has expired. Enter again to continue.')
        ->and(catalog()->forDecision($revoked))->not->toBe(catalog()->forDecision($expired));
});

it('falls to the group default when a site set no discriminator', function (): void {
    // A group lookup returns an array, which is not a message — without the `.default` step this
    // would silently drop through to the literal and the group would never be used.
    $decision = Decision::deny(Decision::SESSION_TERMINATED, 'Some literal.');

    expect(catalog()->forDecision($decision))->toBe('This impersonation is no longer active.');
});

it('interpolates the context a refusal already carries', function (): void {
    $decision = Decision::deny(
        Decision::REASON_REQUIRED,
        'The reason must be between 3 and 500 characters.',
        ['detail' => 'length', 'min' => 3, 'max' => 500],
    );

    expect(catalog()->forDecision($decision))->toBe('The reason must be between 3 and 500 characters.');
});

it('selects a plural form rather than printing both', function (): void {
    // Replaces a hand-rolled `impersonation(s)`. Without `choice()` the pipe-separated line renders
    // whole, which is a worse output than the thing it set out to fix.
    $one = Decision::deny(Decision::CONCURRENCY_LIMIT, 'x', ['count' => 1, 'active' => 1, 'max' => 1]);
    $many = Decision::deny(Decision::CONCURRENCY_LIMIT, 'x', ['count' => 3, 'active' => 3, 'max' => 3]);

    expect(catalog()->forDecision($one))->toBe('You already have 1 active impersonation, which is the limit.')
        ->and(catalog()->forDecision($many))->toBe('You already have 3 active impersonations, which is the limit.')
        ->and(catalog()->forDecision($one))->not->toContain('|');
});

it('drops non-scalar context rather than printing Array', function (): void {
    app('translator')->addLines(['decisions.protected_role' => 'Blocked by :roles.'], 'en', 'laranail-impersonator');

    $decision = Decision::deny(Decision::PROTECTED_ROLE, 'Fallback.', ['roles' => ['admin', 'owner']]);

    // The placeholder goes unreplaced, which is poor — but `Blocked by Array.` is worse.
    expect(catalog()->forDecision($decision))->not->toContain('Array');
});

it('keeps one message for all four token failures', function (): void {
    // The no-oracle property, at the translation layer. Four keys here would rebuild exactly what
    // Core's single PUBLIC_MESSAGE exists to prevent: telling somebody probing the accept route that
    // a token merely expired tells them the token was real.
    $lines = require dirname(__DIR__, 2) . '/resources/lang/en/exceptions.php';

    expect($lines['token_rejected'])->toBeString();

    foreach (['unknown', 'expired', 'already_used', 'revoked'] as $reason) {
        expect(catalog()->get('exceptions.token_rejected.' . $reason, 'FALLBACK'))->toBe('FALLBACK');
    }
});

it('does distinguish the four approval reasons, which are safe to distinguish', function (): void {
    // The opposite of the token case: an approver is authenticated and looking at a request they were
    // shown, so "somebody answered first" leaks nothing.
    $messages = [];

    foreach (['unknown', 'already_decided', 'expired', 'self_approval'] as $reason) {
        $messages[] = catalog()->get('exceptions.approval_not_decidable.' . $reason, 'FALLBACK');
    }

    expect($messages)->not->toContain('FALLBACK')
        ->and(array_unique($messages))->toHaveCount(4);
});

it('has a line for every decision code the package can emit', function (): void {
    // Guards the gap between adding a code and remembering to translate it. Not a hard requirement —
    // the fallback covers it — but an untranslated code is a gap somebody chose, not one that crept in.
    $lines = require dirname(__DIR__, 2) . '/resources/lang/en/decisions.php';

    $constants = new ReflectionClass(Decision::class)->getConstants();
    $missing = [];

    foreach ($constants as $name => $code) {
        if (is_string($code) && ! array_key_exists($code, $lines)) {
            $missing[] = $name . ' (' . $code . ')';
        }
    }

    expect($missing)->toBe([]);
});

it('resolves every shipped line through the loaded namespace', function (): void {
    // The product-demo-mode bug class: a file whose lines exist but whose namespace was never
    // registered, so every lookup renders the raw key. Asserted per file, since registration is what
    // silently fails — and per file rather than once, because a new file is exactly what gets added
    // without checking.
    foreach (['decisions', 'exceptions', 'modes', 'banner', 'console', 'notifications', 'validation', 'components'] as $file) {
        expect(app('translator')->has('laranail-impersonator::' . $file . '.' . array_key_first(
            require dirname(__DIR__, 2) . '/resources/lang/en/' . $file . '.php',
        )))->toBeTrue();
    }
});

it('counts console summaries with a plural form rather than a spliced s', function (): void {
    // `row%s` is only correct in a language that pluralises like English, and wrong even in English
    // for an irregular noun. Asserted at both boundaries, since off-by-one is the whole risk.
    expect(trans_choice('laranail-impersonator::console.verify_audit.intact', 1, ['count' => 1]))
        ->toBe('1 audit row verified. The chain is intact.')
        ->and(trans_choice('laranail-impersonator::console.verify_audit.intact', 4, ['count' => 4]))
        ->toBe('4 audit rows verified. The chain is intact.')
        ->and(trans_choice('laranail-impersonator::console.prune_tokens.pruned', 1, ['count' => 1]))
        ->toBe('1 impersonation handoff token pruned.')
        ->and(trans_choice('laranail-impersonator::console.prune_approvals.expired', 0, ['count' => 0]))
        ->toBe('0 impersonation approval requests expired.');
});

it('gives each approval outcome a whole subject rather than splicing an adjective', function (): void {
    // Word order is not universal: `request :outcome` cannot be translated correctly into a language
    // that puts the outcome first, and reads as machine output when it is forced.
    $subjects = [];

    foreach (['approved', 'denied', 'expired'] as $outcome) {
        $subjects[] = (string) __('laranail-impersonator::notifications.approval.decided.subject_' . $outcome, ['app' => 'Acme']);
    }

    expect(array_unique($subjects))->toHaveCount(3);

    foreach ($subjects as $subject) {
        expect($subject)->toStartWith('[Acme]')
            // No dangling placeholder, which is what a missing key would leave behind.
            ->and($subject)->not->toContain(':');
    }
});

it('localises the date instead of escaping an English word into its format', function (): void {
    // The old format string escaped the English word "at" *into* itself, so a French locale produced
    // a French month beside an English preposition. No lang file could fix that — the offending word
    // was inside a date format rather than in a sentence — which is why the notification changed.
    //
    // Asserted behaviourally rather than by grepping the source: a docblock explaining the old format
    // necessarily quotes it, so a source check flags its own documentation.
    // Built directly rather than through a real impersonation: this is about how one instant is
    // formatted, and a database round trip would add nothing but a fixture to maintain.
    $session = new ImpersonationSession(
        auditId: '01hq000000000000000000000',
        impersonator: new Identity('user', 1),
        target: new Identity('user', 2),
        mode: Mode::of(Mode::FULL),
        guards: new Guards('web', 'web'),
        driver: 'session',
        adapter: 'session',
        startedAt: new DateTimeImmutable('2026-08-12 14:30:00'),
    );

    app()->setLocale('fr');

    $mail = new TargetAccountAccessed($session)->toMail(new stdClass);
    $rendered = implode(' ', array_map(strval(...), $mail->introLines));

    expect($rendered)->not->toContain(' at ')
        // Carbon's French month for that instant, proving the month name itself is translated — which
        // plain `format()` never does, whatever the application locale is set to.
        ->and($rendered)->toContain(
            Carbon::instance($session->startedAt)->locale('fr')->translatedFormat('F'),
        );
});

it('references no translation key that does not exist', function (): void {
    // The other half of the product-demo-mode bug: a `__()` call naming a file, or a nesting, that was
    // never shipped. Laravel renders the raw key for those and nothing fails.
    //
    // Scoped to actual translation calls rather than every `laranail-impersonator::` literal, because Laravel
    // shares the `namespace::` syntax between lang keys and **view** names — `laranail-impersonator::components.badge`
    // is a Blade view, and a sweep that could not tell the two apart reported it as a missing line.
    $keys = [];

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(dirname(__DIR__, 2) . '/src')) as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        preg_match_all(
            "/(?:__|trans|trans_choice|Lang::has|Lang::get)\\(\\s*'laranail-impersonator::([a-z_]+\\.[a-z_.]+)'/",
            (string) file_get_contents($file->getPathname()),
            $m,
        );

        foreach ($m[1] as $key) {
            // A trailing separator means the call concatenates a runtime value onto a prefix. Those
            // cannot be resolved statically, so their concrete cases are asserted below instead.
            if (! str_ends_with($key, '.') && ! str_ends_with($key, '_')) {
                $keys[$key] = $file->getFilename();
            }
        }
    }

    expect($keys)->not->toBeEmpty();

    $missing = [];

    foreach ($keys as $key => $file) {
        if (! Lang::has('laranail-impersonator::' . $key)) {
            $missing[] = $key . ' (' . $file . ')';
        }
    }

    expect($missing)->toBe([]);
});

it('ships every case of the dynamically built keys', function (): void {
    // The keys the sweep above cannot see, because the calling code concatenates a runtime value onto
    // a prefix. Enumerated by hand precisely because a static check cannot reach them.
    $cases = [
        'notifications.target.mode.' => ['read_only', 'limited', 'default'],
        'notifications.approval.decided.subject_' => ['approved', 'denied', 'expired'],
        'notifications.security.summary.' => ['revoked', 'full_mode_enter', 'expired', 'default'],
        'modes.' => ['full.name', 'full.short', 'read_only.name', 'read_only.short', 'limited.name', 'limited.short'],
        'console.doctor.' => ['heading', 'failed', 'warnings', 'clean', 'check_failed', 'wrong_type'],
    ];

    $missing = [];

    foreach ($cases as $prefix => $suffixes) {
        foreach ($suffixes as $suffix) {
            if (! Lang::has('laranail-impersonator::' . $prefix . $suffix)) {
                $missing[] = $prefix . $suffix;
            }
        }
    }

    expect($missing)->toBe([]);
});
