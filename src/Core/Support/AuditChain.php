<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Support;

use SensitiveParameter;

/**
 * The tamper-evidence chain over audit rows.
 *
 * Each row stores a keyed digest of the previous row's digest plus its own opening facts, so
 * altering a row, deleting one, or inserting one after the fact breaks the chain from that
 * point on and `verify-audit` reports where.
 *
 * **Keyed, not a bare hash, and that is the whole point.** A plain `sha256(previous + payload)`
 * chain is recomputable by anyone who knows the algorithm — which is anyone with write access
 * to the table, i.e. precisely the attacker this is meant to detect. They would edit a row and
 * rewrite every digest after it. With an HMAC they cannot, unless they also hold the key, which
 * is why the key belongs outside the database.
 *
 * **What the chain covers, and what it does not.** Only the row's *opening* facts: who
 * impersonated whom, when, in which mode, on which driver, and why. The terminal fields —
 * `ended_at`, `ended_by`, `revoked_at`, the credential details — are written later by design,
 * so including them would break the chain during normal operation. This detects a record being
 * removed or rewritten, which is the realistic attack; it does not attest to how a session
 * ended.
 *
 * Pure and framework-free, so the chain can be verified by anything that can compute an HMAC —
 * including a script that is not this application.
 */
final readonly class AuditChain
{
    /** The digest recorded for the very first row, whose predecessor does not exist. */
    public const string GENESIS = 'genesis';

    public function __construct(
        #[SensitiveParameter]
        private string $key,
    ) {}

    /**
     * The digest for a row, given its predecessor's.
     *
     * @param array<string, mixed> $facts the row's immutable opening facts
     */
    public function digest(array $facts, ?string $previousHash): string
    {
        return hash_hmac(
            'sha256',
            ($previousHash ?? self::GENESIS) . "\n" . $this->canonicalise($facts),
            $this->key,
        );
    }

    /**
     * Whether a row's recorded digest matches what its facts and predecessor imply.
     *
     * `hash_equals` rather than `===`: a timing-safe comparison costs nothing here and this is
     * exactly the kind of check that gets copied into a context where it matters.
     *
     * @param array<string, mixed> $facts
     */
    public function verify(array $facts, ?string $previousHash, string $recordedHash): bool
    {
        return hash_equals($this->digest($facts, $previousHash), $recordedHash);
    }

    /**
     * A deterministic string for a set of facts.
     *
     * @param array<array-key, mixed> $facts
     *
     * Keys are sorted and values normalised, because the digest has to be reproducible from a
     * database row years later — by a different PHP version, a different JSON extension, or a
     * script in another language. Anything order- or format-dependent would make the chain
     * report tampering where there was none, which would be worse than no chain at all.
     */
    public function canonicalise(array $facts): string
    {
        $normalised = [];

        foreach ($facts as $key => $value) {
            $normalised[(string) $key] = $this->scalarise($value);
        }

        ksort($normalised);

        $parts = [];

        foreach ($normalised as $key => $value) {
            $parts[] = $key . '=' . $value;
        }

        // A separator that cannot appear in a normalised value, so `a=1&b=2` and `a=1&b` are
        // never the same string.
        return implode("\x1f", $parts);
    }

    /**
     * A stable string for one value.
     *
     * Null and empty string are distinguished on purpose: "no reason given" and "an empty reason"
     * are different facts, and collapsing them would let one be edited into the other undetected.
     */
    private function scalarise(mixed $value): string
    {
        return match (true) {
            $value === null                  => "\x00null",
            is_bool($value)                  => $value ? "\x00true" : "\x00false",
            is_int($value), is_float($value) => (string) $value,
            is_string($value)                => $value,
            is_array($value)                 => $this->canonicalise($value),
            default                          => "\x00" . get_debug_type($value),
        };
    }
}
