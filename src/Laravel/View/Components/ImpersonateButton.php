<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\View\Components;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Contracts\View\View;
use Illuminate\Database\Eloquent\Model;
use Illuminate\View\Component;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * `<x-impersonate-button :user="$user" />` — a POST form that enters an account.
 *
 * Two decisions make this safe to scatter through a user table:
 *
 *  - **It renders nothing unless the same policy that authorizes the action allows
 *    it.** A button hidden by different logic from the endpoint eventually shows a
 *    control that 403s, or hides one that would have worked. Both are answered by
 *    one call here.
 *  - **It is a form, not a link.** Entering an account changes state, so it cannot be
 *    a GET that a crawler, a prefetcher or a pasted URL can trigger. The CSRF token
 *    comes with the form.
 *
 * Unstyled by default and it forwards its attribute bag, so a host application's own
 * button classes apply without publishing the view.
 */
class ImpersonateButton extends Component
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
        public Authenticatable|Model|null $user = null,
        public ?string $mode = null,
        public ?string $reason = null,
        public ?string $redirectTo = null,
        public ?string $label = null,
        public bool $confirm = false,
    ) {}

    public function render(): View|string
    {
        if ($this->user === null) {
            return '';
        }

        $manager = app(ImpersonationManager::class);

        $settings = app(Settings::class);
        $reasonRequired = $settings->bool('reason.require', false);

        // The visibility question is "may this operator reach this account", not "is
        // this submission complete". When a reason is mandatory the form collects one,
        // so a placeholder is passed here — otherwise the reason rule would hide the
        // very control through which the reason gets supplied.
        $probeReason = $this->reason ?? ($reasonRequired ? 'reason supplied at submit' : null);

        if ($manager->canImpersonate($this->user, $this->mode, reason: $probeReason)->denied()) {
            return '';
        }

        // Assigned onto the property, not just into the view data. Blade exposes a component's public
        // properties to its template, and that exposure *shadows* same-named render data — so a null
        // property rendered an empty label while the data array held the right one.
        $this->label ??= (string) __('laranail-impersonator::components.impersonate');

        return $this->renderView('laranail-impersonator::components.impersonate-button', [
            'user' => $this->user,
            'action' => $this->action($settings),
            'targetType' => $manager->identities()->aliasFor(
                $this->user instanceof Model ? $this->user->getMorphClass() : $this->user::class,
            ),
            'targetId' => $this->user instanceof Model
                ? $this->user->getKey()
                : $this->user->getAuthIdentifier(),
            'mode' => $this->mode,
            'reason' => $this->reason,
            'redirectTo' => $this->redirectTo,
            'label' => $this->label,
            'confirm' => $this->confirm,
            'displayName' => $manager->displayNameFor($this->user),
            'reasonRequired' => $reasonRequired,
        ]);
    }

    /**
     * The enter endpoint, resolved by route name with a config-built path fallback so
     * the component still works in an application that registered its own routes.
     */
    private function action(Settings $settings): string
    {
        $name = $settings->string('routes.name_prefix', 'impersonator.').'enter';

        if (app('router')->has($name)) {
            return route($name);
        }

        return '/'.trim(
            trim($settings->string('routes.prefix', 'impersonator'), '/')
            .'/'.trim($settings->string('routes.enter_path', 'enter'), '/'),
            '/',
        );
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
