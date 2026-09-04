<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\View\Components;

use Illuminate\View\Component;
use Illuminate\Contracts\View\View;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/**
 * `<x-when-impersonating>…</x-when-impersonating>` — renders its slot only during an
 * impersonation, optionally only in a given mode.
 *
 * The component form of the `@impersonating` directive, for applications that prefer
 * components or that need to pass the session into the slot. The state is read from
 * the server, so a template cannot be made to lie about whether impersonation is
 * active.
 */
class WhenImpersonating extends Component
{
    public function __construct(
        public ?string $mode = null,
        public bool $unless = false,
    ) {}

    public function render(): View|string
    {
        $manager = app(ImpersonationManager::class);
        $session = $manager->current();

        $matches = $session !== null
            && ($this->mode === null || $session->mode->is($this->mode));

        if ($this->unless === $matches) {
            return '';
        }

        return $this->renderView('laranail-impersonator::components.slot', ['impersonation' => $session]);
    }

    /**
     * Resolve one of the package's own views.
     *
     * Goes through the view factory rather than the `view()` helper because the helper
     * is typed for verifiable application views, and these are namespaced package
     * views the analyser cannot resolve — the factory takes a plain string.
     *
     * @param array<string, mixed> $data
     */
    private function renderView(string $name, array $data = []): View
    {
        return app(ViewFactory::class)->make($name, $data);
    }
}
