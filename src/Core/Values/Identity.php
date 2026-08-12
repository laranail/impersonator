<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Values;

use Simtabi\Laranail\Impersonator\Core\Exceptions\InvalidIdentity;
use Stringable;

/**
 * A framework-agnostic reference to a user.
 *
 * The Core layer cannot depend on Illuminate\Contracts\Auth\Authenticatable, so
 * every actor crossing a Core boundary is reduced to a (type, id) pair. `type`
 * is the morph alias when one is registered and the fully-qualified class name
 * otherwise — the same string the audit row stores, which is what makes an
 * audit trail resolvable years after the row was written.
 */
final readonly class Identity implements Stringable
{
    public function __construct(
        public string $type,
        public int|string $id,
        public ?string $label = null,
    ) {
        if (trim($type) === '') {
            throw InvalidIdentity::emptyType();
        }

        if ($id === '' || (is_string($id) && trim($id) === '')) {
            throw InvalidIdentity::emptyId();
        }
    }

    public static function of(string $type, int|string $id, ?string $label = null): self
    {
        return new self($type, $id, $label);
    }

    /**
     * Two identities are the same actor when both halves match. The comparison
     * is deliberately loose on the id's PHP type: a route parameter arrives as
     * the string "7" while Eloquent hands back the integer 7, and treating
     * those as different actors is how self-impersonation checks get bypassed.
     */
    public function is(self $other): bool
    {
        return $this->type === $other->type
            && (string) $this->id === (string) $other->id;
    }

    public function isNot(self $other): bool
    {
        return ! $this->is($other);
    }

    /** A stable key for cache entries, locks and de-duplication. */
    public function key(): string
    {
        return $this->type . ':' . $this->id;
    }

    public function withLabel(?string $label): self
    {
        return new self($this->type, $this->id, $label);
    }

    /** @return array{type: string, id: int|string, label: string|null} */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'id' => $this->id,
            'label' => $this->label,
        ];
    }

    /** @param array{type: string, id: int|string, label?: string|null} $data */
    public static function fromArray(array $data): self
    {
        return new self($data['type'], $data['id'], $data['label'] ?? null);
    }

    public function __toString(): string
    {
        return $this->key();
    }
}
