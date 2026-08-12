<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

it('logs a start with structured context', function (): void {
    $captured = [];

    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::enter($this->target, reason: 'Ticket #4182');

    expect($captured)->toHaveCount(1)
        ->and($captured[0]->level)->toBe('info')
        ->and($captured[0]->message)->toBe('Impersonation started.')
        ->and($captured[0]->context['impersonator'])->toBe('user:' . $this->admin->getKey())
        ->and($captured[0]->context['target'])->toBe('user:' . $this->target->getKey())
        ->and($captured[0]->context['mode'])->toBe('full')
        ->and($captured[0]->context['reason'])->toBe('Ticket #4182');
});

it('logs a rejection at the higher rejection level', function (): void {
    // A successful impersonation is routine; an operator probing accounts they
    // cannot reach is what an alert should fire on.
    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    try {
        Impersonator::enter($this->admin);
    } catch (ImpersonationDenied) {
        // expected
    }

    expect($captured)->toHaveCount(1)
        ->and($captured[0]->level)->toBe('warning')
        ->and($captured[0]->message)->toBe('Impersonation rejected.')
        ->and($captured[0]->context['decision'])->toBe('self_impersonation');
});

it('logs a voluntary leave at the ordinary level', function (): void {
    Impersonator::enter($this->target);

    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::leave();

    expect($captured)->toHaveCount(1)
        ->and($captured[0]->level)->toBe('info')
        ->and($captured[0]->context['ended_by'])->toBe('left')
        ->and($captured[0]->context)->toHaveKey('duration_seconds');
});

it('logs an involuntary end at the rejection level', function (): void {
    // A revocation or an expiry means something intervened, which is a security
    // event rather than a routine one.
    Impersonator::enter($this->target);

    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::leave(EndReason::Revoked);

    expect($captured[0]->level)->toBe('warning')
        ->and($captured[0]->context['ended_by'])->toBe('revoked');
});

it('never writes a credential hash or session id into a log', function (): void {
    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::enter($this->target);
    $sessionId = session()->getId();
    Impersonator::leave();

    $serialised = json_encode(array_map(
        static fn ($m): array => ['message' => $m->message, 'context' => $m->context],
        $captured,
    ));

    expect($serialised)->not->toContain($sessionId)
        ->and($serialised)->not->toContain(hash('sha256', $sessionId));
});

it('writes nothing when logging is disabled', function (): void {
    config()->set('impersonator.logging.enabled', false);

    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::enter($this->target);

    expect($captured)->toBe([]);
});

it('degrades an unrecognised log level to the default rather than throwing', function (): void {
    config()->set('impersonator.logging.level', 'shout');

    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::enter($this->target);

    expect($captured[0]->level)->toBe('info');
});

it('honours a configured log level', function (): void {
    config()->set('impersonator.logging.level', 'notice');

    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::enter($this->target);

    expect($captured[0]->level)->toBe('notice');
});
