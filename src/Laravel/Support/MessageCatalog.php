<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Illuminate\Contracts\Translation\Translator;
use Simtabi\Laranail\Impersonator\Core\Values\Decision;

/**
 * Turns a Core refusal into a sentence in the reader's language.
 *
 * Translation happens **here, at the render seam**, and not in Core. Core builds a `Decision` or
 * throws an exception carrying a stable machine code plus an English literal; this class swaps the
 * literal for a translation when one exists. That keeps Core free of a translator contract, and it is
 * the only reason a framework-free domain layer can produce localised output at all.
 *
 * **The code is the contract, the message is not.** `reason` in every API response is the code; it
 * never moves. `message` is display text and may change with the locale — which is exactly what
 * `docs/tools/rest-api.md` tells consumers to branch on and not to branch on.
 *
 * ### Why the lookup cascades
 *
 * A decision code is **not** a unique message identifier, which is easy to assume and wrong. Three
 * different sentences share `session_terminated` — already ended, ended by an administrator, expired
 * — and four share `hierarchy_violation`. Keying translations on the code alone would collapse them
 * into one, so an operator whose session an administrator killed would read that it had expired.
 *
 * So the lookup runs specific → general → literal:
 *
 *   1. `impersonator::decisions.{code}.{detail}` when the decision carries a `detail` context key
 *   2. `impersonator::decisions.{code}` — for a code whose line is a plain string
 *   3. `impersonator::decisions.{code}.default` — for a code whose lines are a group
 *   4. the English literal Core already built
 *
 * The last step is what makes this safe to adopt incrementally: a code with no key yet renders exactly
 * as it does today. Nothing is silently blanked, and no key is mandatory.
 *
 * ### Plurals
 *
 * A line containing `|` is resolved through the translator's `choice()` rather than `get()`, counted on
 * the `count` context entry. Without that a pipe-separated line would render *both* forms verbatim,
 * separated by a pipe — which is how a hand-rolled `impersonation(s)` gets replaced by something worse.
 */
final readonly class MessageCatalog
{
    public function __construct(private Translator $translator) {}

    /**
     * The display message for a refusal.
     *
     * The decision's `context` is passed as replacements, so a key may use `:placeholder` for the
     * counts and names the English literal builds with `sprintf`. Extra context entries are harmless
     * — Laravel ignores replacements a string does not reference.
     */
    public function forDecision(Decision $decision): string
    {
        $fallback = $decision->reason ?? 'That action is not permitted.';

        if ($decision->code === null) {
            return $fallback;
        }

        return $this->lookup(
            'decisions.' . $decision->code,
            $this->detailOf($decision),
            $fallback,
            $decision->context,
        );
    }

    /**
     * The display message for an exception, given the code it reports.
     *
     * Separate from `forDecision()` because an exception's code comes from `code()` or `reason()`
     * rather than from a `Decision`, and its fallback is the message the exception was constructed
     * with.
     *
     * @param array<string, mixed> $replace
     */
    public function forException(string $code, string $fallback, array $replace = []): string
    {
        return $this->lookup('exceptions.' . $code, null, $fallback, $replace);
    }

    /**
     * A plain key with an English fallback, for anything that is neither.
     *
     * @param array<string, mixed> $replace
     */
    public function get(string $key, string $fallback, array $replace = []): string
    {
        return $this->lookup($key, null, $fallback, $replace);
    }

    /**
     * Resolve specific → general → literal.
     *
     * `has()` before `get()` throughout, because Laravel's translator returns the *key* when it finds
     * nothing. Without the guard a missing key renders as `impersonator::decisions.target_busy` in a
     * user's browser, which is worse than the untranslated English it replaced.
     *
     * @param array<string, mixed> $replace
     */
    private function lookup(string $key, ?string $detail, string $fallback, array $replace): string
    {
        $namespaced = 'impersonator::' . $key;

        // `.default` last, so a code whose lines are a group still resolves when the refusing site set
        // no discriminator — a group lookup returns an array, which is not a usable message.
        $candidates = $detail === null
            ? [$namespaced, $namespaced . '.default']
            : [$namespaced . '.' . $detail, $namespaced, $namespaced . '.default'];

        $replacements = $this->replacements($replace);
        $count = $this->countOf($replace);

        foreach ($candidates as $candidate) {
            if (! $this->translator->has($candidate)) {
                continue;
            }

            $raw = $this->translator->get($candidate, $replacements);

            if (! is_string($raw) || $raw === '' || $raw === $candidate) {
                continue;
            }

            // Pluralised lines have to go through `choice()`, which selects a form; `get()` returns the
            // whole pipe-separated string. Counted only when a count is actually available, since
            // `choice()` with a wrong count picks the wrong form silently.
            if ($count !== null && str_contains($raw, '|')) {
                $chosen = $this->translator->choice($candidate, $count, $replacements);

                return is_string($chosen) && $chosen !== '' ? $chosen : $raw;
            }

            return $raw;
        }

        return $fallback;
    }

    /**
     * The optional discriminator that separates two sentences sharing one code.
     *
     * Read from `context.detail` rather than from a new Core type: it is data the decision already
     * carries a slot for, so distinguishing a message costs a context entry at the call site and no
     * new contract anywhere.
     */
    private function detailOf(Decision $decision): ?string
    {
        $detail = $decision->context['detail'] ?? null;

        return is_string($detail) && $detail !== '' ? $detail : null;
    }

    /**
     * The count a pluralised line should be selected on.
     *
     * An explicit `count` entry only. Guessing from whichever numeric context value happens to be
     * present would pick `max` as readily as `active` and choose the wrong form.
     *
     * @param array<string, mixed> $context
     */
    private function countOf(array $context): ?int
    {
        $count = $context['count'] ?? null;

        return is_int($count) ? $count : (is_numeric($count) ? (int) $count : null);
    }

    /**
     * Context narrowed to what a translation line can actually interpolate.
     *
     * Non-scalars are dropped rather than stringified. A context value is frequently a class name, an
     * array of role names or a nested detail bag, and `Array` appearing mid-sentence in a user-facing
     * refusal is worse than the placeholder going unreplaced.
     *
     * @param array<string, mixed> $context
     * @return array<string, string>
     */
    private function replacements(array $context): array
    {
        $replace = [];

        foreach ($context as $key => $value) {
            if (is_scalar($value)) {
                $replace[$key] = (string) $value;
            }
        }

        return $replace;
    }
}
