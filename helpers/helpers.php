<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Laravel\ImpersonationManager;

if (! function_exists('impersonator')) {
    /**
     * The impersonation manager.
     *
     * Guarded by function_exists so an application that already defines this
     * name keeps its own. Autoloaded files cannot be conditionally excluded, so
     * this is the only way a helper can be shipped without risking a fatal
     * redeclaration on install.
     */
    function impersonator(): ImpersonationManager
    {
        return app(ImpersonationManager::class);
    }
}
