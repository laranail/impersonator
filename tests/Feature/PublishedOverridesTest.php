<?php

declare(strict_types=1);

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\ServiceProvider;
use Simtabi\Laranail\Impersonator\Laravel\Support\DeprecatedNames;
use Simtabi\Laranail\Impersonator\Laravel\Providers\ImpersonatorServiceProvider;

/*
 * A published override is only worth publishing if something reads it.
 *
 * Laravel reads view overrides from `resources/views/vendor/{namespace}` and translation overrides
 * from `lang/vendor/{namespace}`, where {namespace} is the one the package's own `view()` / `__()`
 * calls use: `laranail-impersonator`. Until this was fixed the tags published to `.../vendor/impersonator`,
 * which no namespace points at, so every published override was silently ignored while the packaged
 * default kept answering. These tests publish through the real command, edit the published copy the
 * way a host would, and render through the namespace the package uses.
 */

/** Every path these tests publish into, removed afterwards so the Testbench skeleton stays clean. */
function impersonatorPublishedPaths(): array
{
    return [
        resource_path('views/vendor/laranail-impersonator'),
        resource_path('views/vendor/impersonator'),
        lang_path('vendor/laranail-impersonator'),
        lang_path('vendor/impersonator'),
    ];
}

beforeEach(function (): void {
    foreach (impersonatorPublishedPaths() as $path) {
        (new Filesystem)->deleteDirectory($path);
    }
});

afterEach(function (): void {
    foreach (impersonatorPublishedPaths() as $path) {
        (new Filesystem)->deleteDirectory($path);
    }
});

it('renders a published view override', function (string $tag): void {
    $this->artisan('vendor:publish', ['--tag' => $tag, '--force' => true])->assertSuccessful();

    $published = resource_path('views/vendor/laranail-impersonator/banner.blade.php');

    expect($published)->toBeFile();

    file_put_contents($published, 'host-override-of-the-banner');

    // A real host boots a fresh application after publishing; the view factory only adds an
    // override directory that exists when it is resolved, so resolve it again.
    $this->app->forgetInstance('view');

    expect($this->app->make('view')->make('laranail-impersonator::banner')->render())
        ->toBe('host-override-of-the-banner')
        ->and($this->app->make('view')->make('laranail/impersonator::banner')->render())
        ->toBe('host-override-of-the-banner');
})->with(['laranail::impersonator-views', 'impersonator-views']);

it('reads a published translation override', function (string $tag): void {
    $this->artisan('vendor:publish', ['--tag' => $tag, '--force' => true])->assertSuccessful();

    $published = lang_path('vendor/laranail-impersonator/en/banner.php');

    expect($published)->toBeFile();

    $lines = require $published;
    $lines['leave'] = 'Host says leave';
    file_put_contents($published, '<?php return ' . var_export($lines, true) . ';');

    $this->app->forgetInstance('translator');

    expect($this->app->make('translator')->get('laranail-impersonator::banner.leave'))->toBe('Host says leave');
})->with(['laranail::impersonator-lang', 'impersonator-lang']);

it('publishes the config where the package reads it', function (string $tag): void {
    $paths = ServiceProvider::pathsToPublish(ImpersonatorServiceProvider::class, $tag);

    expect($paths)->toHaveCount(1)
        ->and(reset($paths))->toBe(config_path('laranail/impersonator.php'));
})->with(['laranail::impersonator-config', 'impersonator-config']);

it('publishes the same files under the scoped and the bare tag', function (string $suffix): void {
    expect(ServiceProvider::pathsToPublish(ImpersonatorServiceProvider::class, 'impersonator-' . $suffix))
        ->not->toBeEmpty()
        ->toBe(ServiceProvider::pathsToPublish(ImpersonatorServiceProvider::class, 'laranail::impersonator-' . $suffix));
})->with(['config', 'views', 'lang', 'migrations']);

it('announces a bare publish tag as deprecated', function (): void {
    DeprecatedNames::forgetWarnings();

    $raised = [];
    set_error_handler(static function (int $level, string $message) use (&$raised): bool {
        $raised[] = $message;

        return true;
    }, E_USER_DEPRECATED);

    try {
        $this->artisan('vendor:publish', ['--tag' => 'impersonator-views', '--force' => true])->assertSuccessful();
        $this->artisan('vendor:publish', ['--tag' => 'laranail::impersonator-lang', '--force' => true])->assertSuccessful();
    } finally {
        restore_error_handler();
        DeprecatedNames::forgetWarnings();
    }

    expect($raised)->toBe([
        DeprecatedNames::message('publish tag', 'impersonator-views', 'laranail::impersonator-views'),
    ]);
});
