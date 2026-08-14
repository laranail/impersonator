<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;
use Simtabi\Laranail\Impersonator\Laravel\Support\RlsContext;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;

/*
| PostgreSQL row-level security.
|
| The inversion this exists to prevent: an application scoping rows by a GUC that still names the
| **operator** shows an impersonated session the operator's own rows while claiming to be the customer.
|
| Two implementation rules are asserted here rather than trusted, because both have a plausible wrong
| version that works in development:
|
|   - bindings, never interpolation — `SET` cannot take a parameter, so the obvious implementation
|     concatenates and becomes an injection hole on a path that handles identity;
|   - transaction scope, never session scope — a session GUC leaks to the next PgBouncer client.
*/

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('laranail.impersonator.limits.state_cache.ttl', 0);

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

it('reports the target as the effective identity while impersonating', function (): void {
    // The whole fix for the inversion, and a one-line change in a host's own scoping layer: read this
    // rather than `auth()->id()`.
    Impersonator::enter($this->target);

    $context = app(RlsContext::class);

    expect($context->effective()?->id)->toBe((string) $this->target->getKey())
        ->and($context->operator()?->id)->toBe((string) $this->admin->getKey())
        ->and($context->isImpersonating())->toBeTrue();
});

it('reports the authenticated user when nobody is impersonating', function (): void {
    $context = app(RlsContext::class);

    // Compared loosely on purpose. `Identity::$id` is `int|string` — an int when built from a live
    // model, a string when read back from an audit row — which is why `Identity::is()` compares loosely
    // too. What matters for RLS is that `gucs()` casts to string, and that is asserted separately.
    expect((string) $context->effective()?->id)->toBe((string) $this->admin->getKey())
        ->and($context->operator())->toBeNull()
        ->and($context->isImpersonating())->toBeFalse()
        // Nothing to publish: an ordinary request must not carry an impersonation context.
        ->and($context->gucs())->toBe([]);
});

it('names both parties and the mode in the gucs', function (): void {
    Impersonator::enter($this->target, mode: 'read_only');

    $gucs = app(RlsContext::class)->gucs();

    expect($gucs['app.impersonated_user_id'])->toBe((string) $this->target->getKey())
        ->and($gucs['app.impersonator_id'])->toBe((string) $this->admin->getKey())
        // The mode is published so a policy can refuse writes under read_only at the database level —
        // defence in depth beside the PHP guard, not instead of it.
        ->and($gucs['app.impersonation_mode'])->toBe('read_only')
        ->and($gucs['app.impersonation_audit_id'])->toBe(Impersonator::current()?->auditId);
});

it('honours a configured guc prefix', function (): void {
    config()->set('laranail.impersonator.rls.prefix', 'tenant');

    Impersonator::enter($this->target);

    expect(array_keys(app(RlsContext::class)->gucs()))
        ->each(fn ($key) => $key->toStartWith('tenant.'));
});

it('sets every guc with bindings and never by interpolation', function (): void {
    // The injection rule. `SET LOCAL app.x = '…'` cannot take a bind parameter, so an implementation
    // reaching for it must concatenate the value — on a path that handles identity. `set_config` is a
    // function call and takes real parameters.
    Impersonator::enter($this->target);

    $statements = [];

    DB::listen(function ($query) use (&$statements): void {
        $statements[] = $query;
    });

    app(RlsContext::class)->applyTo(DB::connection());

    expect($statements)->not->toBeEmpty();

    foreach ($statements as $statement) {
        expect($statement->sql)->toBe('select set_config(?, ?, true)')
            // Two bindings, and the values live there rather than in the SQL.
            ->and($statement->bindings)->toHaveCount(2)
            ->and($statement->sql)->not->toContain('SET LOCAL')
            ->and($statement->sql)->not->toContain((string) $this->target->getKey());
    }
})->skip(fn (): bool => DB::connection()->getDriverName() !== 'pgsql', 'set_config is PostgreSQL-only');

it('sets the gucs transaction-scoped, not session-scoped', function (): void {
    // `true` is the third argument to set_config, and it is the difference between a GUC that dies with
    // the transaction and one that leaks to the next client PgBouncer hands the connection to.
    Impersonator::enter($this->target);

    $statements = [];
    DB::listen(function ($query) use (&$statements): void {
        $statements[] = $query->sql;
    });

    app(RlsContext::class)->applyTo(DB::connection());

    foreach ($statements as $sql) {
        expect($sql)->toContain('true')
            ->and($sql)->not->toContain('false');
    }
})->skip(fn (): bool => DB::connection()->getDriverName() !== 'pgsql', 'set_config is PostgreSQL-only');

it('survives a name a caller could have crafted', function (): void {
    // The prefix comes from config, so it is not attacker-controlled — but the values are identity, and
    // the point of bindings is that neither can alter the statement.
    config()->set('laranail.impersonator.rls.prefix', 'app');

    $crafted = User::create(['name' => "'; drop table impersonator_audits; --"]);

    Impersonator::enter($crafted);

    $statements = [];
    DB::listen(function ($query) use (&$statements): void {
        $statements[] = $query;
    });

    app(RlsContext::class)->applyTo(DB::connection());

    foreach ($statements as $statement) {
        expect($statement->sql)->toBe('select set_config(?, ?, true)');
    }

    // The table is still there, which a concatenating implementation could not promise.
    expect(Schema::hasTable('impersonator_audits'))->toBeTrue();
})->skip(fn (): bool => DB::connection()->getDriverName() !== 'pgsql', 'set_config is PostgreSQL-only');
