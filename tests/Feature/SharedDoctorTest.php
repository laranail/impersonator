<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Laravel\Doctor\Check;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks;
use Simtabi\Laranail\Impersonator\Laravel\Doctor\Checks\RestApiCheck;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorCheck;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorResult;
use Simtabi\Laranail\Package\Tools\Services\Doctor\DoctorService;

/*
| The family integration.
|
| These checks are registered into package-tools' shared DoctorService, so an operator running
| `laranail::package-tools.doctor` across every installed laranail package sees impersonation's
| findings alongside the rest — rather than having to know this package ships a doctor of its own.
|
| One list feeds both commands. A second list is how the two would come to disagree.
*/

it('registers every check into the shared doctor service', function (): void {
    // The integration itself. `getChecks()` returns instances, so compare by class.
    $registered = array_map(
        static fn (DoctorCheck $check): string => $check::class,
        app(DoctorService::class)->getChecks(),
    );

    foreach (Checks::all() as $class) {
        expect($registered)->toContain($class);
    }
});

it('registers instances, because the service cannot inject a constructor', function (): void {
    // `DoctorService::register()` instantiates a string argument with a bare `new $check` — no
    // container, no arguments. Our checks take Settings, so registering by class name would raise an
    // ArgumentCountError at boot. This asserts the shape that avoids it.
    $registered = app(DoctorService::class)->getChecks();

    $ours = array_filter($registered, static fn (DoctorCheck $c): bool => $c instanceof Check);

    expect($ours)->not->toBeEmpty()
        ->and(count($ours))->toBe(count(Checks::all()));
});

it('groups its checks under the package name', function (): void {
    // So an operator reading a family-wide report can tell which package raised what.
    $report = app(DoctorService::class)->run();

    $groups = [];

    foreach ($report as $row) {
        if ($row['check'] instanceof Check) {
            $groups[] = $row['group'];
        }
    }

    expect(array_unique($groups))->toBe(['laranail/impersonator']);
});

it('every check satisfies the shared contract', function (): void {
    foreach (Checks::all() as $class) {
        $check = app($class);

        expect($check)->toBeInstanceOf(DoctorCheck::class)
            ->and($check)->toBeInstanceOf(Check::class)
            ->and($check->name())->not->toBe('')
            ->and($check->description())->not->toBe('');
    }
});

it('no check throws, whatever the configuration', function (): void {
    // The contract says `run()` never throws, and the doctor is the thing somebody runs *because*
    // the install is broken. Driven against deliberately hostile config: a missing hash key is the
    // state that makes the audit store throw on construction, which is exactly what used to take
    // the doctor down with it.
    config()->set('laranail.impersonator.audit.tamper_evident', true);
    config()->set('laranail.impersonator.audit.hash_key', null);
    config()->set('laranail.impersonator.targets.allowlist', ['ghost' => 'App\\Models\\NotInstalled']);
    config()->set('laranail.impersonator.guards.impersonator', 'nonexistent-guard');
    config()->set('laranail.impersonator.driver', 'token');
    config()->set('laranail.impersonator.api.enabled', true);
    config()->set('laranail.impersonator.api.middleware', ['api']);
    config()->set('laranail.impersonator.approval.require', true);
    config()->set('laranail.impersonator.limits.max_duration', null);
    config()->set('laranail.impersonator.limits.extension.max', null);
    config()->set('laranail.impersonator.limits.extension.max_total_duration', null);

    foreach (Checks::all() as $class) {
        $result = app($class)->run();

        expect($result)->toBeInstanceOf(DoctorResult::class)
            ->and($result->message)->not->toBe('');
    }
});

it('never leaks the audit hash key into a check result', function (): void {
    // The key lives outside the database on purpose. A diagnostic that echoed it would put it in
    // whatever terminal, CI log or pasted issue the operator was working in.
    $secret = 'sk-'.str_repeat('z', 60);

    config()->set('laranail.impersonator.audit.tamper_evident', true);
    config()->set('laranail.impersonator.audit.hash_key', $secret);

    foreach (Checks::all() as $class) {
        $result = app($class)->run();

        expect($result->message)->not->toContain($secret)
            ->and(json_encode($result->detail))->not->toContain($secret);
    }
});

it('reports the same findings through both commands', function (): void {
    // The property that makes one shared list worth having.
    config()->set('laranail.impersonator.api.enabled', true);
    config()->set('laranail.impersonator.api.middleware', ['api']);

    $own = $this->artisan('laranail::impersonator.doctor');
    $own->expectsOutputToContain('unauthenticated remote-control surface');
    $own->assertFailed();
    $own->run();

    // The same check object, reached the way the shared runner reaches it.
    $result = app(RestApiCheck::class)->run();

    expect($result->message)->toContain('unauthenticated remote-control surface');
});
