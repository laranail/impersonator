<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\View\Components;

use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Contracts\View\View;
use Illuminate\View\Component;
use Simtabi\Laranail\Impersonator\Laravel\Support\BannerPresenter;

/**
 * `<x-impersonator-banner />` — the "you are viewing as somebody else" bar.
 *
 * Renders nothing at all when there is no impersonation, so it can be dropped once
 * into a layout and left there. That is the whole design goal: a host application
 * should not have to wrap it in a conditional, because the conditional is exactly
 * what people forget, and a banner that fails to appear is a silent one.
 *
 * Attributes override config per placement, so a layout used by two panels can show
 * the banner at the top in one and the bottom in the other without a config change.
 */
class ImpersonationBanner extends Component
{
    public function __construct(
        public ?string $theme = null,
        public ?string $position = null,
        public ?bool $showMode = null,
        public ?bool $showDuration = null,
    ) {}

    public function render(): View|string
    {
        $data = app(BannerPresenter::class)->data();

        // Empty string rather than a null view: a component returning null throws,
        // and "nothing to announce" is the common case, not an error.
        if ($data === null) {
            return '';
        }

        return $this->renderView('impersonator::banner', [
            ...$data,
            'theme' => $this->theme ?? $data['theme'],
            'position' => $this->position ?? $data['position'],
            'showMode' => $this->showMode ?? $data['showMode'],
            'showDuration' => $this->showDuration ?? $data['showDuration'],
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
