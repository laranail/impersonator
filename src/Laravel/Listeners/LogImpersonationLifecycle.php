<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Listeners;

use DateTimeImmutable;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Log\LogManager;
use Psr\Log\LoggerInterface;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalDenied;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalGranted;
use Simtabi\Laranail\Impersonator\Core\Events\ApprovalRequested;
use Simtabi\Laranail\Impersonator\Core\Events\HandoffTokenIssued;
use Simtabi\Laranail\Impersonator\Core\Events\HandoffTokenRedeemed;
use Simtabi\Laranail\Impersonator\Core\Events\HandoffTokenRejected;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationEnded;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationExpired;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationExtended;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRejected;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRequested;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationRevoked;
use Simtabi\Laranail\Impersonator\Core\Events\ImpersonationStarted;
use Simtabi\Laranail\Impersonator\Core\Events\ModeViolationBlocked;
use Simtabi\Laranail\Impersonator\Core\Events\TargetNotified;
use Simtabi\Laranail\Impersonator\Core\Support\Redactor;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationRequest;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Throwable;

/**
 * Writes every lifecycle transition to a PSR-3 channel with structured context.
 *
 * OWASP's Logging Cheat Sheet asks for *all actions by* privileged users and explicitly for *use of a
 * break-glass account*. Logging only the successful starts and ends misses both: the interesting lines
 * are the refusals, the boundary probes and the approvals.
 *
 * ### Three things shape what is here
 *
 * **Refusals log at a higher level than successes.** A successful impersonation is routine; an
 * operator repeatedly attempting accounts they cannot reach is what an alert should fire on. So is a
 * `read_only` session attempting writes — that is either an application bug or somebody working around
 * the boundary, and it is the single most security-relevant signal this package emits.
 *
 * **Every line carries `audit_id`.** One value greps a whole impersonation — its start, every mode
 * violation inside it, its extensions, its end. Without a correlation id a trail is a pile of lines
 * that happen to mention the same account. {@see HandoffTokenRejected} is the sole exception, and by
 * construction: a rejected token has no audit row, so it is keyed on the IP and reason it carries.
 *
 * **Context is flat scalars, keyed consistently.** A log aggregator can facet on `impersonator`,
 * `target` or `decision` across every event without per-event parsing rules.
 *
 * ### What never appears
 *
 * No token plaintext, credential secret, credential hash, session id or approval fingerprint — a hash
 * is still a verifier that lets a holder confirm a guess, and a fingerprint is what a permit is matched
 * on. `ImpersonationSession::toArray()` already omits the first three by construction; the rest is
 * enforced by only ever writing the fields named here, and asserted by a test that drives all sixteen
 * events and greps every context for them.
 */
final readonly class LogImpersonationLifecycle
{
    public function __construct(
        private LogManager $logs,
        private Config $config,
    ) {}

    // ── The impersonation itself ─────────────────────────────────────────────

    /**
     * An attempt begins, **before** authorization.
     *
     * Logged for refused attempts too, which is the point: a listener counting attempts needs the true
     * rate rather than only the successes. At debug level, because on a busy install this is the
     * highest-volume line here and it says nothing on its own — the interesting one is whatever follows.
     */
    public function handleRequested(ImpersonationRequested $event): void
    {
        $this->write('debug', 'Impersonation requested.', $this->fromRequest($event->request));
    }

    public function handleStarted(ImpersonationStarted $event): void
    {
        $this->write($this->level(), 'Impersonation started.', [
            ...$this->fromSession($event->session),
            'driver' => $event->session->driver,
            'adapter' => $event->session->adapter,
            'tenant_id' => $event->session->tenantId,
            'reason' => $event->session->reason,
            'expires_at' => $event->session->expiresAt?->format(DATE_ATOM),
        ], audit: true);
    }

    public function handleEnded(ImpersonationEnded $event): void
    {
        // An involuntary end is a security event rather than a routine one: a revocation or an expiry
        // says something intervened.
        $level = $event->reason->isInvoluntary() ? $this->rejectionLevel() : $this->level();

        $this->write($level, 'Impersonation ended.', [
            ...$this->fromSession($event->session),
            'ended_by' => $event->reason->value,
            'duration_seconds' => $event->session->durationInSeconds(new DateTimeImmutable),
        ], audit: true);
    }

    public function handleRejected(ImpersonationRejected $event): void
    {
        $this->write($this->rejectionLevel(), 'Impersonation rejected.', [
            ...$this->fromRequest($event->request),
            'decision' => $event->decision->code,
            'reason' => $event->decision->reason,
            'decision_context' => $this->scrub($event->decision->context),
        ]);
    }

    /**
     * Extended from inside a live session.
     *
     * Logged because the point of a short window is that staying longer is a decision somebody made
     * rather than a default nobody noticed. A trail showing three extensions on one account answers a
     * question a single row reading "fifty minutes" cannot.
     */
    public function handleExtended(ImpersonationExtended $event): void
    {
        $this->write($this->level(), 'Impersonation extended.', [
            ...$this->fromSession($event->session),
            'seconds_added' => $event->grant->seconds(),
            'extensions' => $event->session->extensions,
            'expires_at' => $event->session->expiresAt?->format(DATE_ATOM),
        ], audit: true);
    }

    /** An administrator pulled the switch. Always at the refusal level: somebody intervened. */
    public function handleRevoked(ImpersonationRevoked $event): void
    {
        $this->write($this->rejectionLevel(), 'Impersonation revoked.', [
            ...$this->fromSession($event->session),
            'revoked_by' => $event->revokedBy?->key(),
            'note' => $event->note,
        ], audit: true);
    }

    public function handleExpired(ImpersonationExpired $event): void
    {
        $this->write($this->rejectionLevel(), 'Impersonation expired.', [
            ...$this->fromSession($event->session),
            'expires_at' => $event->session->expiresAt?->format(DATE_ATOM),
        ], audit: true);
    }

    /**
     * An impersonated session attempted something its mode forbids.
     *
     * **The most security-relevant line this package emits**, and the one that was previously dispatched
     * and written nowhere. A `read_only` session attempting a write is either an application bug or an
     * operator working around the boundary, and neither is visible anywhere else.
     */
    public function handleModeViolation(ModeViolationBlocked $event): void
    {
        $this->write($this->rejectionLevel(), 'Mode violation blocked.', [
            ...$this->fromSession($event->session),
            'decision' => $event->decision->code,
            'attempted_method' => $event->action->normalizedMethod(),
            'attempted_path' => $event->action->path,
            'attempted_route' => $event->action->routeName,
            'attempted_model' => $event->action->modelClass,
        ], audit: true);
    }

    // ── Handoff tokens ───────────────────────────────────────────────────────

    public function handleTokenIssued(HandoffTokenIssued $event): void
    {
        $this->write($this->level(), 'Handoff token issued.', $this->fromSession($event->session));
    }

    public function handleTokenRedeemed(HandoffTokenRedeemed $event): void
    {
        $this->write($this->level(), 'Handoff token redeemed.', $this->fromSession($event->session));
    }

    /**
     * A token was refused, with the **real** reason.
     *
     * The reason goes here and never to the client: telling somebody probing the accept route that a
     * token merely expired tells them the token was real. This is the only line without an `audit_id`,
     * because a rejected token has no audit row — it is keyed on the IP instead, which is what a
     * rate-limit alert would group on anyway.
     */
    public function handleTokenRejected(HandoffTokenRejected $event): void
    {
        $this->write($this->rejectionLevel(), 'Handoff token rejected.', [
            'token_reason' => $event->reason,
            'ip' => $event->ip,
        ]);
    }

    // ── Break-glass approvals ────────────────────────────────────────────────

    public function handleApprovalRequested(ApprovalRequested $event): void
    {
        $this->write($this->level(), 'Approval requested.', [
            'approval_id' => $event->approvalId,
            ...$this->fromRequest($event->request),
        ], audit: true);
    }

    /**
     * One reviewer approved.
     *
     * Per reviewer, not per final transition. A chain whose intermediate approvals are invisible cannot
     * answer "who signed off" during a review — which is the entire question an audit of a four-eyes
     * control asks.
     */
    public function handleApprovalGranted(ApprovalGranted $event): void
    {
        $this->write($this->level(), 'Approval granted.', [
            'approval_id' => $event->approvalId,
            ...$this->fromRequest($event->request),
            'approved_by' => $event->approvedBy->key(),
        ], audit: true);
    }

    public function handleApprovalDenied(ApprovalDenied $event): void
    {
        // An expiry is the clock rather than a person, so it is not a refusal by anybody — but it is
        // still the outcome of a request nobody answered, which is worth the higher level.
        $this->write($this->rejectionLevel(), 'Approval denied.', [
            'approval_id' => $event->approvalId,
            'denied_by' => $event->deniedBy?->key(),
            'note' => $event->note,
            'expired' => $event->expired,
        ], audit: true);
    }

    public function handleTargetNotified(TargetNotified $event): void
    {
        $this->write($this->level(), 'Target notified.', [
            ...$this->fromSession($event->session),
            'channel' => $event->channel,
        ]);
    }

    // ── Shared shape ─────────────────────────────────────────────────────────

    /**
     * The fields every session-bearing line shares.
     *
     * `audit_id` first and always: it is the correlation id that makes a whole impersonation greppable
     * with one value.
     *
     * @return array<string, mixed>
     */
    private function fromSession(ImpersonationSession $session): array
    {
        return [
            'audit_id' => $session->auditId,
            'impersonator' => $session->impersonator->key(),
            'target' => $session->target->key(),
            'mode' => $session->mode->name,
        ];
    }

    /**
     * The same shape for an event that has a request but no session yet.
     *
     * No `audit_id`, because there is no row — a request that was refused never produced one.
     *
     * @return array<string, mixed>
     */
    private function fromRequest(ImpersonationRequest $request): array
    {
        return [
            'impersonator' => $request->impersonator->key(),
            'target' => $request->target->key(),
            'mode' => $request->mode->name,
            'driver' => $request->driver,
            'ip' => $request->ip,
        ];
    }

    /**
     * Write one line, to the ordinary channel and — when tamper-relevant — the audit channel too.
     *
     * @param  array<string, mixed>  $context
     * @param  bool  $audit  whether this line belongs in the separable audit sink
     */
    private function write(string $level, string $message, array $context, bool $audit = false): void
    {
        if ($this->config->get('laranail.impersonator.logging.enabled', true) !== true) {
            return;
        }

        $context = array_filter(
            $context,
            static fn (mixed $value): bool => $value !== null && $value !== [],
        );

        $this->channel()->log($level, $message, $context);

        // A second write rather than a rerouting, so the ordinary channel stays complete. An operator
        // reading application logs during an incident should not have to know that the interesting
        // lines went somewhere else.
        $audit && $this->auditChannel()?->log($level, $message, $context);
    }

    private function channel(): LoggerInterface
    {
        $channel = $this->config->get('laranail.impersonator.logging.channel');

        return is_string($channel) && $channel !== ''
            ? $this->logs->channel($channel)
            : $this->logs->driver();
    }

    /**
     * The separable audit sink, or null when none is configured.
     *
     * ASVS 16.4.2/16.4.3 require that logs cannot be modified and are shipped off-box, and an audit
     * table writable by the application's own database user does not meet that on its own. The HMAC
     * chain gives tamper *evidence*, not tamper *resistance* — only an external sink closes the gap.
     *
     * Resolution failures are swallowed on purpose: a mistyped channel name must not turn every
     * impersonation into an exception. The ordinary line has already been written by the time this
     * runs, so the worst case is a missing copy rather than a missing record.
     */
    private function auditChannel(): ?LoggerInterface
    {
        $channel = $this->config->get('laranail.impersonator.logging.audit_channel');

        if (! is_string($channel) || $channel === '') {
            return null;
        }

        try {
            return $this->logs->channel($channel);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * A decision's own context, with anything sensitive replaced.
     *
     * Refusal context is the one place arbitrary data reaches a log line here: it is assembled at the
     * refusing call site and may carry whatever that site thought useful. Scrubbed through the same
     * redactor the request trail uses and against the same configured key list, so a key considered
     * sensitive in one place is not written in the other.
     *
     * @param  array<string, mixed>  $context
     * @return array<string, mixed>
     */
    private function scrub(array $context): array
    {
        $keys = $this->config->get('laranail.impersonator.trail.redact');

        return Redactor::for(is_array($keys) ? array_values(array_filter($keys, is_string(...))) : [])
            ->scrub($context);
    }

    private function level(): string
    {
        return $this->normalise($this->config->get('laranail.impersonator.logging.level'), 'info');
    }

    private function rejectionLevel(): string
    {
        return $this->normalise($this->config->get('laranail.impersonator.logging.rejection_level'), 'warning');
    }

    /**
     * A level PSR-3 recognises. An unrecognised name would make the logger throw on a lifecycle event,
     * so a bad config value degrades to the default rather than turning an impersonation into an
     * exception.
     */
    private function normalise(mixed $level, string $default): string
    {
        $allowed = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'];

        return is_string($level) && in_array(strtolower($level), $allowed, true)
            ? strtolower($level)
            : $default;
    }
}
