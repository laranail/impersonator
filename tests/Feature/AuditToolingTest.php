<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Contracts\Auth\Access\Gate;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\User;
use Simtabi\Laranail\Impersonator\Tests\Fixtures\RbacUser;
use Simtabi\Laranail\Impersonator\Laravel\Audit\AuditExporter;
use Simtabi\Laranail\Impersonator\Laravel\Support\TargetRegistry;
use Simtabi\Laranail\Impersonator\Laravel\Authorization\RbacPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Laravel\Policies\ImpersonationAuditPolicy;
use Simtabi\Laranail\Impersonator\Laravel\Middleware\RecordImpersonationTrail;
use Simtabi\Laranail\Impersonator\Laravel\Facades\ImpersonatorFacade as Impersonator;

beforeEach(function (): void {
    Schema::create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->json('permissions')->nullable();
        $table->json('roles')->nullable();
        $table->timestamps();
        $table->softDeletes();
    });

    config()->set('laranail.impersonator.targets.allowlist', ['user' => User::class]);
    config()->set('auth.providers.users.model', User::class);
    config()->set('laranail.impersonator.limits.max_active_per_impersonator', 10);

    Route::middleware(['web', RecordImpersonationTrail::class])->group(function (): void {
        Route::get('/app/page', fn (): string => 'page')->name('page');
        Route::post('/app/save', fn (): string => 'saved')->name('save');
    });

    $this->admin = User::create(['name' => 'Admin']);
    $this->target = User::create(['name' => 'Customer']);

    $this->startSession();
    Auth::guard('web')->setUser($this->admin);
});

// ── export ──────────────────────────────────────────────────────────────────

it('exports an impersonation and its trail as json', function (): void {
    $auditId = Impersonator::enter($this->target, reason: 'Ticket #4182')->auditId();
    $this->get('/app/page');
    $this->post('/app/save');

    $document = json_decode(app(AuditExporter::class)->export($auditId), true);

    expect($document['impersonation']['id'])->toBe($auditId)
        ->and($document['impersonation']['reason'])->toBe('Ticket #4182')
        ->and($document['trail_events'])->toBe(2)
        ->and($document['trail'])->toHaveCount(2)
        ->and($document['trail'][0]['path'])->toBe('/app/page')
        ->and($document['exported_at'])->toBeString();
});

it('never puts the credential hash or session id in an export', function (): void {
    // An export leaves the building — attached to a ticket, mailed to a regulator. A digest is
    // still a verifier for a guessed token, so it carries the facts and none of the credentials.
    $auditId = Impersonator::enter($this->target)->auditId();
    $row = ImpersonationAudit::query()->findOrFail($auditId);

    $json = app(AuditExporter::class)->export($auditId);

    expect($json)->not->toContain((string) $row->getAttribute('credential_hash'))
        ->and($json)->not->toContain((string) $row->getAttribute('session_id'))
        ->and($json)->not->toContain('credential_hash')
        ->and($json)->not->toContain('session_id');
});

it('exports as csv in two sections', function (): void {
    // Not a flat table: an impersonation and its actions are one-to-many, and flattening would
    // repeat the session facts on every row.
    $auditId = Impersonator::enter($this->target)->auditId();
    $this->get('/app/page');

    $csv = app(AuditExporter::class)->export($auditId, AuditExporter::CSV);

    expect($csv)->toContain('section,field,value')
        ->and($csv)->toContain('impersonation,id,' . $auditId)
        ->and($csv)->toContain('occurred_at,method,path')
        ->and($csv)->toContain('/app/page');
});

it('writes csv a standards-compliant reader can parse', function (): void {
    // The export exists to be read by somebody else's tooling — Excel, a regulator's script,
    // pandas. PHP's historic `fputcsv` escape (`\\`) is not RFC 4180: it backslash-escapes a
    // quote instead of doubling it. Round-tripping through PHP's own `fgetcsv` cannot catch that,
    // because that reader is symmetric with the writer; every other parser corrupts the field.
    //
    // The `payload` column is JSON, so it is full of quotes and backslashes. This is the column
    // where it actually went wrong.
    config()->set('laranail.impersonator.trail.record_payloads', true);

    $auditId = Impersonator::enter($this->target)->auditId();
    $this->post('/app/save', ['note' => 'C:\\Users\\admin', 'said' => 'say "hi"']);

    $csv = app(AuditExporter::class)->export($auditId, AuditExporter::CSV);

    // Deliberately no assertion on the raw bytes. The JSON payload contains `\"` as *data*, so
    // its presence proves nothing either way — only reading the file back with a compliant parser
    // separates correct output from corrupted output.
    //
    // `escape: ''` here is that parser. With PHP's legacy default this loop yields a payload cell
    // that no longer decodes, which is precisely what the auditor's tooling would hit.
    $rows = [];
    $handle = fopen('php://temp', 'r+');
    fwrite($handle, $csv);
    rewind($handle);

    while (($row = fgetcsv($handle, escape: '')) !== false) {
        $rows[] = $row;
    }

    fclose($handle);

    $payloads = array_filter(array_map(
        static fn (array $row): string => is_string(end($row)) ? end($row) : '',
        $rows,
    ), static fn (string $cell): bool => str_starts_with($cell, '{'));

    expect($payloads)->not->toBeEmpty();

    // Every payload cell must still be valid JSON after the trip through CSV. Corruption shows up
    // here as a decode failure, which is exactly what the auditor would hit.
    foreach ($payloads as $payload) {
        expect(json_decode($payload, true))->toBeArray();
    }
});

it('exports through the command to stdout', function (): void {
    $auditId = Impersonator::enter($this->target)->auditId();

    $this->artisan('laranail::impersonator.export-audit', ['audit' => $auditId])
        ->assertSuccessful();
});

it('writes the export to a file when asked', function (): void {
    $auditId = Impersonator::enter($this->target)->auditId();
    $path = sys_get_temp_dir() . '/impersonator-export-' . bin2hex(random_bytes(4)) . '.json';

    $this->artisan('laranail::impersonator.export-audit', [
        'audit'    => $auditId,
        '--output' => $path,
    ])->assertSuccessful();

    expect(file_exists($path))->toBeTrue()
        ->and(json_decode((string) file_get_contents($path), true)['impersonation']['id'])->toBe($auditId);

    unlink($path);
});

it('refuses an unknown format', function (): void {
    $auditId = Impersonator::enter($this->target)->auditId();

    $this->artisan('laranail::impersonator.export-audit', [
        'audit'    => $auditId,
        '--format' => 'xml',
    ])->assertFailed();
});

it('reports a missing audit row rather than exporting nothing', function (): void {
    $this->artisan('laranail::impersonator.export-audit', ['audit' => 'nope'])->assertFailed();
});

// ── tamper evidence ─────────────────────────────────────────────────────────

it('writes no chain when tamper evidence is off', function (): void {
    $auditId = Impersonator::enter($this->target)->auditId();

    expect(ImpersonationAudit::query()->findOrFail($auditId)->getAttribute('hash'))->toBeNull();
});

it('chains rows when tamper evidence is on', function (): void {
    config()->set('laranail.impersonator.audit.tamper_evident', true);
    config()->set('laranail.impersonator.audit.hash_key', str_repeat('k', 64));

    $first = Impersonator::enter($this->target)->auditId();
    Impersonator::leave();
    $second = Impersonator::enter($this->target)->auditId();

    $rows = ImpersonationAudit::query()->orderBy('started_at')->orderBy('id')->get();

    expect($rows[0]->getAttribute('hash'))->toBeString()
        ->and($rows[0]->getAttribute('previous_hash'))->toBeNull()
        ->and($rows[1]->getAttribute('previous_hash'))->toBe($rows[0]->getAttribute('hash'))
        ->and($first)->not->toBe($second);
});

it('refuses to boot the chain without a key', function (): void {
    // A chain written with a key nobody recorded cannot be verified later, so silently deriving
    // one would produce an audit trail that only looks tamper-evident.
    config()->set('laranail.impersonator.audit.tamper_evident', true);
    config()->set('laranail.impersonator.audit.hash_key', null);

    expect(fn () => Impersonator::enter($this->target))->toThrow(InvalidArgumentException::class);
});

it('verifies an intact chain', function (): void {
    config()->set('laranail.impersonator.audit.tamper_evident', true);
    config()->set('laranail.impersonator.audit.hash_key', str_repeat('k', 64));

    Impersonator::enter($this->target);
    Impersonator::leave();
    Impersonator::enter($this->target);

    $this->artisan('laranail::impersonator.verify-audit')->assertSuccessful();
});

it('detects an altered row', function (): void {
    config()->set('laranail.impersonator.audit.tamper_evident', true);
    config()->set('laranail.impersonator.audit.hash_key', str_repeat('k', 64));

    $auditId = Impersonator::enter($this->target, reason: 'Ticket #1')->auditId();

    // Straight to the database, so no model event or observer can normalise it back.
    DB::table('impersonator_audits')->where('id', $auditId)->update(['reason' => 'Ticket #999']);

    $this->artisan('laranail::impersonator.verify-audit')->assertFailed();
});

it('detects a deleted row by the break it leaves in the chain', function (): void {
    config()->set('laranail.impersonator.audit.tamper_evident', true);
    config()->set('laranail.impersonator.audit.hash_key', str_repeat('k', 64));

    $first = Impersonator::enter($this->target)->auditId();
    Impersonator::leave();
    Impersonator::enter($this->target);

    DB::table('impersonator_audits')->where('id', $first)->delete();

    $this->artisan('laranail::impersonator.verify-audit')->assertFailed();
});

it('cannot be verified with a different key', function (): void {
    config()->set('laranail.impersonator.audit.tamper_evident', true);
    config()->set('laranail.impersonator.audit.hash_key', str_repeat('k', 64));

    Impersonator::enter($this->target);

    config()->set('laranail.impersonator.audit.hash_key', str_repeat('z', 64));

    $this->artisan('laranail::impersonator.verify-audit')->assertFailed();
});

it('says plainly that there is nothing to verify when the feature is off', function (): void {
    Impersonator::enter($this->target);

    $this->artisan('laranail::impersonator.verify-audit')->assertSuccessful();
});

it('skips rows written before tamper evidence was switched on', function (): void {
    // Reporting a break for rows that never had a digest would make the command useless on every
    // existing installation.
    Impersonator::enter($this->target)->auditId();
    Impersonator::leave();

    config()->set('laranail.impersonator.audit.tamper_evident', true);
    config()->set('laranail.impersonator.audit.hash_key', str_repeat('k', 64));

    Impersonator::enter($this->target);

    $this->artisan('laranail::impersonator.verify-audit')->assertSuccessful();
});

// ── CLI enter ───────────────────────────────────────────────────────────────

it('enters from the console and prints an accept URL', function (): void {
    config()->set('laranail.impersonator.driver', 'token');
    config()->set('laranail.impersonator.urls.base_domain', 'app.example.com');

    $this->artisan('laranail::impersonator.enter', [
        'user'     => (string) $this->target->getKey(),
        '--as'     => (string) $this->admin->getKey(),
        '--reason' => 'On-call escalation',
    ])->assertSuccessful();

    expect(ImpersonationAudit::query()->count())->toBe(1)
        ->and(ImpersonationAudit::query()->first()?->getAttribute('reason'))->toBe('On-call escalation');
});

it('records that the impersonation came from the console', function (): void {
    // Console-initiated impersonation warrants different scrutiny from one started through a UI.
    config()->set('laranail.impersonator.driver', 'token');
    config()->set('laranail.impersonator.urls.base_domain', 'app.example.com');

    $this->artisan('laranail::impersonator.enter', [
        'user' => (string) $this->target->getKey(),
        '--as' => (string) $this->admin->getKey(),
    ])->assertSuccessful();

    expect(ImpersonationAudit::query()->first()?->getAttribute('metadata')['entered_via'])
        ->toBe('console');
});

it('warns that the printed URL is a live credential', function (): void {
    config()->set('laranail.impersonator.driver', 'token');
    config()->set('laranail.impersonator.urls.base_domain', 'app.example.com');

    $this->artisan('laranail::impersonator.enter', [
        'user' => (string) $this->target->getKey(),
        '--as' => (string) $this->admin->getKey(),
    ])->expectsOutputToContain('live single-use credential');
});

it('says there is no URL for an in-process driver', function (): void {
    config()->set('laranail.impersonator.driver', 'session');

    $this->artisan('laranail::impersonator.enter', [
        'user' => (string) $this->target->getKey(),
        '--as' => (string) $this->admin->getKey(),
    ])->expectsOutputToContain('no accept URL');
});

it('requires an operator so the audit row names a real person', function (): void {
    $this->artisan('laranail::impersonator.enter', ['user' => (string) $this->target->getKey()])
        ->assertFailed();
});

it('refuses an ambiguous bare id when several target types are registered', function (): void {
    // Guessing which type was meant could enter the wrong account entirely.
    config()->set('laranail.impersonator.targets.allowlist', [
        'user'  => User::class,
        'staff' => RbacUser::class,
    ]);
    app(TargetRegistry::class)->flush();

    $this->artisan('laranail::impersonator.enter', [
        'user' => (string) $this->target->getKey(),
        '--as' => (string) $this->admin->getKey(),
    ])->assertFailed()->expectsOutputToContain('Qualify it as type:id');
});

it('accepts a qualified type:id', function (): void {
    config()->set('laranail.impersonator.driver', 'token');
    config()->set('laranail.impersonator.urls.base_domain', 'app.example.com');

    $this->artisan('laranail::impersonator.enter', [
        'user' => 'user:' . $this->target->getKey(),
        '--as' => 'user:' . $this->admin->getKey(),
    ])->assertSuccessful();
});

it('reports a refusal with its decision code', function (): void {
    $this->artisan('laranail::impersonator.enter', [
        'user' => (string) $this->admin->getKey(),
        '--as' => (string) $this->admin->getKey(),
    ])->assertFailed()->expectsOutputToContain('self_impersonation');
});

// ── audit policy ────────────────────────────────────────────────────────────

it('gates audit reads through the same policy the API uses', function (): void {
    config()->set('laranail.impersonator.targets.allowlist', ['user' => RbacUser::class]);
    config()->set('auth.providers.users.model', RbacUser::class);
    config()->set(
        'laranail.impersonator.authorization.policy',
        RbacPolicy::class,
    );

    $viewer = RbacUser::create(['name' => 'Viewer', 'permissions' => ['impersonator.audit.view']]);
    $nobody = RbacUser::create(['name' => 'Nobody', 'permissions' => []]);

    $policy = app(ImpersonationAuditPolicy::class);

    // No audit row is passed to `view` or `export`, and that is the point: reading the trail is a
    // blanket permission, so those methods take only the user. `$user->can('view', $audit)` still
    // works — Laravel passes the model and PHP ignores the extra argument — but asserting it here
    // with a row would imply a per-row decision the policy does not make. Only `revoke` is per-row.
    expect($policy->viewAny($viewer))->toBeTrue()
        ->and($policy->view($viewer))->toBeTrue()
        ->and($policy->export($viewer))->toBeTrue()
        ->and($policy->viewAny($nobody))->toBeFalse();
});

it('gates revocation separately from reading', function (): void {
    // An auditor who may read every impersonation has no business ending one.
    config()->set('laranail.impersonator.targets.allowlist', ['user' => RbacUser::class]);
    config()->set('auth.providers.users.model', RbacUser::class);
    config()->set(
        'laranail.impersonator.authorization.policy',
        RbacPolicy::class,
    );

    $reader = RbacUser::create(['name' => 'Reader', 'permissions' => ['impersonator.audit.view']]);
    $ender = RbacUser::create(['name' => 'Ender', 'permissions' => ['impersonator.revoke']]);

    $policy = app(ImpersonationAuditPolicy::class);
    $audit = new ImpersonationAudit;

    expect($policy->revoke($reader, $audit))->toBeFalse()
        ->and($policy->revoke($ender, $audit))->toBeTrue()
        ->and($policy->viewAny($ender))->toBeFalse();
});

it('registers the policy on the gate', function (): void {
    expect(app(Gate::class)->getPolicyFor(ImpersonationAudit::class))
        ->toBeInstanceOf(ImpersonationAuditPolicy::class);
});
