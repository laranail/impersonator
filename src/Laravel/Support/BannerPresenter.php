<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Routing\Router;
use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

/**
 * Assembles the banner's view data.
 *
 * Split out of the view so the labels, the theme and the leave URL are all
 * testable without rendering Blade, and so a published banner template does not
 * carry logic a consumer would then have to maintain through upgrades.
 */
final readonly class BannerPresenter
{
    public function __construct(
        private ImpersonationManager $impersonator,
        private Settings $settings,
        private UrlGenerator $url,
        private Router $router,
        private ViewFactory $views,
    ) {}

    /**
     * The rendered banner, or an empty string when there is nothing to announce.
     *
     * Empty rather than null so `@impersonationBanner` can echo the result
     * unconditionally — a directive that had to null-check would print "1" or
     * nothing depending on the caller's Blade version.
     */
    public function render(): string
    {
        $data = $this->data();

        return $data === null ? '' : $this->views->make('impersonator::banner', $data)->render();
    }

    /**
     * View data, or null when there is nothing to announce — not impersonating,
     * or the banner is switched off.
     *
     * @return array<string, mixed>|null
     */
    public function data(): ?array
    {
        if (! $this->settings->bool('banner.enabled', true)) {
            return null;
        }

        $session = $this->impersonator->current();

        if ($session === null) {
            return null;
        }

        return [
            'impersonation' => $session,
            'theme' => $this->theme(),
            'position' => $this->position(),
            'targetName' => $this->label($session->target->label, $this->impersonator->target()),
            'impersonatorName' => $this->label($session->impersonator->label, $this->impersonator->actor()),
            'showMode' => $this->settings->bool('banner.show_mode', true),
            'showDuration' => $this->settings->bool('banner.show_duration', true),
            'expiresAt' => $session->expiresAt,
            'leaveUrl' => $this->leaveUrl(),
        ];
    }

    /**
     * The leave URL, or a plain path when the route is not registered.
     *
     * Falling back rather than throwing is deliberate: an application that
     * registers its own routes would otherwise get an exception from the banner on
     * every page, and a banner whose button is wrong is far better than a banner
     * that takes the site down.
     */
    public function leaveUrl(): string
    {
        $name = $this->settings->string('routes.name_prefix', 'impersonator.') . 'leave';

        if ($this->router->has($name)) {
            return $this->url->route($name);
        }

        return '/' . trim(
            trim($this->settings->string('routes.prefix', 'impersonator'), '/')
            . '/' . trim($this->settings->string('routes.leave_path', 'leave'), '/'),
            '/',
        );
    }

    private function theme(): string
    {
        return $this->settings->enum('banner.theme', ['auto', 'light', 'dark'], 'auto');
    }

    private function position(): string
    {
        return $this->settings->enum('banner.position', ['top', 'bottom'], 'bottom');
    }

    /**
     * Prefer the label captured in the audit row over the live model: the row
     * records who the account was at the time, and a name changed since then
     * should not silently rewrite what the banner reported.
     */
    private function label(?string $recorded, Authenticatable|Model|null $user): ?string
    {
        if ($recorded !== null && $recorded !== '') {
            return $recorded;
        }

        return $user === null ? null : $this->impersonator->displayNameFor($user);
    }
}
