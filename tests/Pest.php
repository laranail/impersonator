<?php

declare(strict_types=1);

use Simtabi\Laranail\Impersonator\Tests\TestCase;

// Feature tests need a booted application; Unit and Arch tests deliberately do
// not get one. That split is what keeps the Core layer honest — a Core test that
// accidentally relies on a container would fail rather than quietly pass.
uses(TestCase::class)->in('Feature');
