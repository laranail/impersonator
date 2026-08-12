<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Exceptions;

use Simtabi\Laranail\Impersonator\Core\Values\Decision;

/**
 * The authorization stack refused an impersonation attempt.
 *
 * Carries the machine-readable Decision so the bridge can log the precise
 * reason and render an appropriate status without string-matching a message.
 */
final class ImpersonationDenied extends ImpersonationException
{
    private function __construct(public readonly Decision $decision)
    {
        parent::__construct($decision->reason ?? 'Impersonation denied.');
    }

    public static function from(Decision $decision): self
    {
        return new self($decision);
    }

    public function code(): string
    {
        return $this->decision->code ?? 'denied';
    }
}
