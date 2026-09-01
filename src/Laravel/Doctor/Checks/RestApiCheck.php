<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;

final class RestApiCheck extends Check
{
    public function name(): string
    {
        return 'REST API';
    }

    public function description(): string
    {
        return 'Whether the impersonation API, if enabled, sits behind an auth guard.';
    }

    public function run(): DoctorResult
    {
        if (! $this->settings->bool('api.enabled', false)) {
            return DoctorResult::pass('Disabled, which is the default.');
        }

        $middleware = $this->settings->stringList('api.middleware');
        $hasAuth = array_any($middleware, static fn (string $m): bool => str_starts_with($m, 'auth'));

        return $hasAuth
            ? DoctorResult::pass(sprintf('Enabled behind [%s].', implode(', ', $middleware)))
            : DoctorResult::fail(sprintf(
                'The API is enabled but its middleware [%s] contains no auth guard. That is an '
                .'unauthenticated remote-control surface for every account in the system.',
                implode(', ', $middleware),
            ));
    }
}
