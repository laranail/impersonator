<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\View\Components;

use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Contracts\View\View;
use Illuminate\View\Component;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\BannerPresenter;

/**
 * `<x-impersonation-badge />` — a compact indicator of the active mode.
 *
 * For placing next to a save button or a form heading, where the banner is too far
 * from the thing the operator is about to do. "You are read-only" and "you can do
 * anything" need to be distinguishable at the point of action, not only at the edge
 * of the viewport.
 *
 * Renders nothing when not impersonating.
 */
class ImpersonationBadge extends Component
{
    public function __construct(
        public bool $showTarget = false,
    ) {}

    public function render(): View|string
    {
        $manager = app(ImpersonationManager::class);
        $presenter = app(BannerPresenter::class);
        $session = $manager->current();

        if ($session === null) {
            return '';
        }

        return $this->renderView('impersonator::components.badge', [
            'mode' => $session->mode->name,
            'modeName' => $presenter->modeName($session->mode->name, short: true),
            'description' => $manager->modes()->descriptions()[$session->mode->name] ?? null,
            'targetName' => $this->showTarget
                ? ($session->target->label ?? $manager->displayNameFor($manager->target()))
                : null,
        ]);
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
