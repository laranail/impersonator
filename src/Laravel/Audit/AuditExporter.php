<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Audit;

use Simtabi\Laranail\Impersonator\Core\Contracts\AuditStore;
use Simtabi\Laranail\Impersonator\Core\Contracts\TrailStore;
use Simtabi\Laranail\Impersonator\Core\Exceptions\AuditRowMissing;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Values\TrailEvent;

/**
 * Renders one impersonation and its full action trail for a compliance request.
 *
 * One implementation shared by the console command and the API endpoint, so an export produced
 * by a support engineer and one pulled by an auditor are byte-for-byte the same document. Two
 * exporters would eventually disagree, and the disagreement would surface during an audit.
 *
 * **The credential hash and session id are never included.** A digest is still a verifier: a
 * holder can confirm a guessed token against it. An export leaves the building — attached to a
 * ticket, mailed to a regulator, pasted into a spreadsheet — so it carries the facts of the
 * impersonation and none of its credentials.
 */
final readonly class AuditExporter
{
    public const string JSON = 'json';

    public const string CSV = 'csv';

    /** Trail pages, so a long session does not load whole. */
    private const int PAGE = 500;

    public function __construct(
        private AuditStore $audits,
        private TrailStore $trail,
    ) {}

    /** @return list<string> */
    public static function formats(): array
    {
        return [self::JSON, self::CSV];
    }

    /** @throws AuditRowMissing when the audit id names no row */
    public function export(string $auditId, string $format = self::JSON): string
    {
        $session = $this->audits->find($auditId) ?? throw AuditRowMissing::for($auditId);

        return match ($format) {
            self::CSV => $this->csv($session),
            default => $this->json($session),
        };
    }

    /** @return array<string, mixed> */
    public function toArray(string $auditId): array
    {
        $session = $this->audits->find($auditId) ?? throw AuditRowMissing::for($auditId);

        return $this->document($session);
    }

    private function json(ImpersonationSession $session): string
    {
        // Pretty-printed and with slashes unescaped: an export is read by people, and
        // `https:\/\/` in a document handed to an auditor is noise that invites questions.
        $json = json_encode(
            $this->document($session),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        );

        return $json . "\n";
    }

    /**
     * CSV, as one section of session facts followed by the trail rows.
     *
     * Not a flat table: an impersonation and its actions are one-to-many, and flattening would
     * repeat the session facts on every row. Spreadsheet software handles the two-section shape,
     * and a human reading it can see the structure.
     */
    private function csv(ImpersonationSession $session): string
    {
        // `escape: ''` on every write, and it is a correctness fix rather than a style choice.
        //
        // PHP's historic default (`\\`) is not RFC 4180: it emits a backslash-escaped quote
        // instead of doubling it, so `say "hi"` inside the JSON `payload` column comes out as
        // something a standards-compliant reader mis-parses. Round-tripping through PHP's own
        // `fgetcsv` hides it — that reader is symmetric with the writer — but Excel, Python's
        // `csv` module and every other RFC parser silently corrupt the field. For a compliance
        // export whose whole purpose is being read by somebody else's tooling, that is the
        // failure that matters, and it is invisible from inside PHP.
        //
        // PHP 8.4 deprecated relying on the default at all, which is what surfaced this.

        $handle = fopen('php://temp', 'r+');

        if ($handle === false) {
            // Falling back rather than failing: an export is a read operation, and returning the
            // JSON form is far better than returning nothing.
            return $this->json($session);
        }

        $document = $this->document($session);

        fputcsv($handle, ['section', 'field', 'value'], escape: '');

        foreach ($this->flatten($document['impersonation']) as $field => $value) {
            fputcsv($handle, ['impersonation', $field, $value], escape: '');
        }

        fputcsv($handle, [], escape: '');
        fputcsv($handle, ['occurred_at', 'method', 'path', 'route', 'status', 'duration_ms', 'payload'], escape: '');

        foreach ($document['trail'] as $event) {
            fputcsv($handle, array_map($this->cell(...), [
                $event['occurred_at'] ?? '',
                $event['method'] ?? '',
                $event['path'] ?? '',
                $event['route_name'] ?? '',
                $event['status'] ?? '',
                $event['duration_ms'] ?? '',
                is_array($event['payload'] ?? null)
                    ? json_encode($event['payload'], JSON_UNESCAPED_SLASHES)
                    : '',
            ]), escape: '');
        }

        rewind($handle);
        $csv = stream_get_contents($handle);
        fclose($handle);

        return $csv === false ? '' : $csv;
    }

    /** One CSV cell, reduced to something the writer accepts. */
    private function cell(mixed $value): string
    {
        return match (true) {
            $value === null, $value === false => '',
            $value === true => 'true',
            is_scalar($value) => (string) $value,
            default => '',
        };
    }

    /** @return array{impersonation: array<string, mixed>, trail: list<array<string, mixed>>, exported_at: string, trail_events: int} */
    private function document(ImpersonationSession $session): array
    {
        // `toArray()` is already the safe projection — it omits the credential hash and session
        // id by construction, so an export cannot leak them by forgetting to.
        return [
            'impersonation' => $session->toArray(),
            'trail_events' => $this->trail->countForAudit($session->auditId),
            'trail' => array_map(
                static fn (TrailEvent $event): array => $event->toArray(),
                $this->allTrailEvents($session->auditId),
            ),
            'exported_at' => now()->toIso8601String(),
        ];
    }

    /** @return list<TrailEvent> */
    private function allTrailEvents(string $auditId): array
    {
        $events = [];
        $offset = 0;

        do {
            $page = $this->trail->forAudit($auditId, self::PAGE, $offset);
            $events = [...$events, ...$page];
            $offset += self::PAGE;
        } while (count($page) === self::PAGE);

        return $events;
    }

    /**
     * @param array<array-key, mixed> $data
     * @return array<string, string>
     */
    private function flatten(array $data, string $prefix = ''): array
    {
        $flat = [];

        foreach ($data as $key => $value) {
            $name = $prefix === '' ? (string) $key : $prefix . '.' . $key;

            if (is_array($value)) {
                $flat = [...$flat, ...$this->flatten($value, $name)];

                continue;
            }

            $flat[$name] = $this->cell($value);
        }

        return $flat;
    }
}
