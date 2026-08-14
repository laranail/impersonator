<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Core\Enums\EndReason;
use Simtabi\Laranail\Impersonator\Core\Exceptions\ImpersonationDenied;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Listeners\LogImpersonationLifecycle;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\EnforceImpersonationMode;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

/**
 * The first captured line with this message.
 *
 * Selected by message rather than by index, and no test asserts a *total* count. Coupling a test to
 * how many lines the package writes altogether means every new event breaks it — which is exactly what
 * happened when `ImpersonationRequested` began logging.
 *
 * @param list<object> $captured
 */
function lineFor(array $captured, string $message): object
{
    foreach ($captured as $line) {
        if ($line->message === $message) {
            return $line;
        }
    }

    throw new RuntimeException(sprintf('no log line said [%s]', $message));
}

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
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

    $line = lineFor($captured, 'Impersonation started.');

    expect($line->level)->toBe('info')
        ->and($line->context['impersonator'])->toBe('user:' . $this->admin->getKey())
        ->and($line->context['target'])->toBe('user:' . $this->target->getKey())
        ->and($line->context['mode'])->toBe('full')
        ->and($line->context['reason'])->toBe('Ticket #4182')
        // The correlation id, on every session-bearing line.
        ->and($line->context['audit_id'])->toBe(Impersonator::current()?->auditId);
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

    $line = lineFor($captured, 'Impersonation rejected.');

    expect($line->level)->toBe('warning')
        ->and($line->context['decision'])->toBe('self_impersonation');
});

it('logs a voluntary leave at the ordinary level', function (): void {
    Impersonator::enter($this->target);

    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::leave();

    $line = lineFor($captured, 'Impersonation ended.');

    expect($line->level)->toBe('info')
        ->and($line->context['ended_by'])->toBe('left')
        ->and($line->context)->toHaveKey('duration_seconds');
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

    $line = lineFor($captured, 'Impersonation ended.');

    expect($line->level)->toBe('warning')
        ->and($line->context['ended_by'])->toBe('revoked');
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
    config()->set('laranail.impersonator.logging.enabled', false);

    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::enter($this->target);

    expect($captured)->toBe([]);
});

it('degrades an unrecognised log level to the default rather than throwing', function (): void {
    config()->set('laranail.impersonator.logging.level', 'shout');

    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::enter($this->target);

    expect(lineFor($captured, 'Impersonation started.')->level)->toBe('info');
});

it('honours a configured log level', function (): void {
    config()->set('laranail.impersonator.logging.level', 'notice');

    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::enter($this->target);

    expect(lineFor($captured, 'Impersonation started.')->level)->toBe('notice');
});

it('has a handler for every event the package dispatches', function (): void {
    // The gap this closes: `ModeViolationBlocked` was dispatched and written nowhere, so a session
    // probing its own boundary left no trace outside the request that produced it. Enumerated from the
    // filesystem rather than a list, because a new event file is exactly what gets added without a
    // handler.
    $events = [];

    foreach (glob(dirname(__DIR__, 2) . '/src/Core/Events/*.php') ?: [] as $file) {
        $events[] = basename($file, '.php');
    }

    $listener = new ReflectionClass(LogImpersonationLifecycle::class);
    $handlers = array_map(
        static fn (ReflectionMethod $m): string => $m->getName(),
        array_filter(
            $listener->getMethods(ReflectionMethod::IS_PUBLIC),
            static fn (ReflectionMethod $m): bool => str_starts_with($m->getName(), 'handle'),
        ),
    );

    expect($events)->toHaveCount(15)
        ->and($handlers)->toHaveCount(15);

    // And every one is actually wired, not merely implemented.
    foreach ($events as $event) {
        $class = 'Simtabi\\Laranail\\Impersonator\\Core\\Events\\' . $event;

        expect(Event::hasListeners($class))->toBeTrue("no listener for {$event}");
    }
});

it('logs a mode violation, which is the signal that had no home', function (): void {
    Route::middleware(['web', EnforceImpersonationMode::class])
        ->post('/app/write', fn (): string => 'ok')
        ->name('write');

    Impersonator::enter($this->target, mode: 'read_only');

    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    $auditId = Impersonator::current()?->auditId;

    $this->post('/app/write');

    $line = lineFor($captured, 'Mode violation blocked.');

    expect($line->level)->toBe('warning')
        ->and($line->context['audit_id'])->toBe($auditId)
        ->and($line->context['decision'])->toBe('mode_forbids_write')
        // What was attempted, so a reviewer can tell a probe from an application bug.
        ->and($line->context)->toHaveKey('attempted_method');
});

it('puts the audit id on every session-bearing line', function (): void {
    // One value greps a whole impersonation — its start, every violation inside it, its extensions and
    // its end. Without it a trail is a pile of lines that happen to mention the same account.
    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    Impersonator::enter($this->target);
    $auditId = Impersonator::current()?->auditId;
    Impersonator::extendSession();
    Impersonator::leave();

    $sessionLines = array_filter(
        $captured,
        static fn ($line): bool => in_array($line->message, [
            'Impersonation started.',
            'Impersonation extended.',
            'Impersonation ended.',
        ], true),
    );

    expect($sessionLines)->toHaveCount(3);

    foreach ($sessionLines as $line) {
        expect($line->context['audit_id'] ?? null)->toBe($auditId, $line->message);
    }
});

it('writes the tamper-relevant subset to a separate audit channel as well', function (): void {
    // ASVS 16.4.2/16.4.3: an audit table writable by the application's own database user is not
    // tamper-resistant. The HMAC chain gives evidence, not resistance — only an off-box sink closes it.
    config()->set('logging.channels.impersonator_audit', ['driver' => 'single', 'path' => storage_path('logs/audit.log')]);
    config()->set('laranail.impersonator.logging.audit_channel', 'impersonator_audit');

    $channels = [];
    Log::listen(function ($message) use (&$channels): void {
        $channels[] = $message->message;
    });

    Impersonator::enter($this->target);

    // Two writes of the same line: the ordinary channel keeps everything, so an operator reading
    // application logs during an incident does not have to know the interesting lines went elsewhere.
    expect(array_count_values($channels)['Impersonation started.'] ?? 0)->toBe(2);
});

it('ignores an audit channel that does not resolve rather than failing an impersonation', function (): void {
    config()->set('laranail.impersonator.logging.audit_channel', 'a-channel-nobody-defined');

    // The ordinary line is written before this is attempted, so a typo costs a copy and not a record.
    expect(fn () => Impersonator::enter($this->target))->not->toThrow(Throwable::class);

    expect(Impersonator::isImpersonating())->toBeTrue();
});

it('never writes a token, a hash, a session id or a fingerprint', function (): void {
    // The rule this package holds itself to is stricter than ASVS 16.2.5, which asks only that session
    // tokens be masked: here they are never written at all. A hash is still a verifier that lets a
    // holder confirm a guess, and a fingerprint is the value a permit is matched on.
    config()->set('laranail.impersonator.driver', 'token');
    config()->set('laranail.impersonator.audit.tamper_evident', true);
    config()->set('laranail.impersonator.audit.hash_key', str_repeat('k', 64));

    $captured = [];
    Log::listen(function ($message) use (&$captured): void {
        $captured[] = $message;
    });

    $outcome = Impersonator::enter($this->target, reason: 'Ticket #9');

    // The token driver returns the plaintext exactly once, on the outcome. Both it and its digest have
    // to be absent from every line — the digest as much as the plaintext, since it verifies a guess.
    $token = $outcome->credential?->secret;
    $accept = $outcome->acceptUrl;

    config()->set('laranail.impersonator.driver', 'session');

    $serialised = (string) json_encode(array_map(
        static fn ($m): array => ['message' => $m->message, 'context' => $m->context],
        $captured,
    ));

    expect($captured)->not->toBeEmpty();

    // The plaintext token, and its digest — the digest matters as much, because it verifies a guess.
    if (is_string($token) && $token !== '') {
        expect($serialised)->not->toContain($token)
            ->and($serialised)->not->toContain(hash('sha256', $token));
    }

    // The accept URL carries a live single-use token in its path, so the whole URL is a secret.
    if (is_string($accept) && $accept !== '') {
        expect($serialised)->not->toContain($accept);
    }

    foreach (['credential_hash', 'session_id', 'fingerprint', 'hash_key', 'secret'] as $forbidden) {
        expect($serialised)->not->toContain($forbidden);
    }
});
