<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\View\Components;

use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Contracts\View\View;
use Illuminate\View\Component;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\BannerPresenter;

/**
 * `<x-impersonation-leave-button />` — a standalone way out.
 *
 * The banner already carries one, so this exists for applications that suppress the
 * banner and put the control in their own chrome. Leaving must be reachable from
 * somewhere no matter how the host styles things: an operator who cannot leave is
 * stuck inside a customer's account.
 *
 * Renders nothing when not impersonating.
 */
class LeaveImpersonationButton extends Component
{
    /**
     * Nullable, and resolved in `render()` rather than defaulted here.
     *
     * A promoted-property default has to be a constant expression, so
     * `public string $label = __('…')` is a parse error rather than a style choice. Null therefore
     * means "use the shipped label"; an explicit `label="…"` on the tag still wins, so nothing about
     * the component's public surface changes.
     */
    public function __construct(
        public ?string $label = null,
    ) {}

    public function render(): View|string
    {
        if (! app(ImpersonationManager::class)->isImpersonating()) {
            return '';
        }

        // Assigned onto the property, not just into the view data. Blade exposes a component's public
        // properties to its template, and that exposure *shadows* same-named render data — so a null
        // property rendered an empty label while the data array held the right one.
        $this->label ??= (string) __('laranail-impersonator::components.leave');

        return $this->renderView('laranail-impersonator::components.leave-button', [
            'url' => app(BannerPresenter::class)->leaveUrl(),
            'label' => $this->label,
        ]);
    }

    /**
     * Resolve one of the package's own views.
     *
     * Goes through the view factory rather than the `view()` helper because the helper
     * is typed for verifiable application views, and these are namespaced package
     * views the analyser cannot resolve — the factory takes a plain string.
     *
     * @param  array<string, mixed>  $data
     */
    private function renderView(string $name, array $data = []): View
    {
        return app(ViewFactory::class)->make($name, $data);
    }
}
