<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

final class TamperEvidenceCheck extends Check
{
    public function name(): string
    {
        return 'Tamper evidence';
    }

    public function description(): string
    {
        return 'Whether the audit hash chain is on, and keyed adequately.';
    }

    public function run(): DoctorResult
    {
        if (! $this->settings->bool('audit.tamper_evident', false)) {
            return DoctorResult::warn(
                'The audit chain is off, so a row that is altered or deleted leaves no trace. Set '
                . 'impersonator.audit.tamper_evident and a hash_key if the trail is evidence.',
            );
        }

        $key = $this->settings->nullableString('audit.hash_key');

        if ($key === null) {
            // Deliberately checked without resolving the audit store, which throws on this exact
            // state. An application here boots cleanly and fails on its first impersonation, so the
            // doctor is the only thing that will say so before a user does.
            return DoctorResult::fail(
                'Enabled but impersonator.audit.hash_key is unset. Every impersonation will fail '
                . 'when the audit store is built. Set a long random key kept outside the database.',
            );
        }

        return strlen($key) < 32
            ? DoctorResult::warn(sprintf('The hash key is %d bytes. Use at least 32.', strlen($key)))
            : DoctorResult::pass('Enabled with a key of adequate length.');
    }
}
