<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Core\Events;

use Simtabi\Laranail\Impersonator\Core\Values\Identity;

/** A pending impersonation was refused, or expired unapproved. */
final readonly class ApprovalDenied
{
    public function __construct(
        public string $approvalId,
        public ?Identity $deniedBy = null,
        public ?string $note = null,
        public bool $expired = false,
    ) {}
}
