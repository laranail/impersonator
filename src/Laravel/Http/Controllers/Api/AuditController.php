<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use Illuminate\Http\Response;
use Illuminate\Pagination\LengthAwarePaginator;
use Simtabi\Laranail\Impersonator\Core\Exceptions\AuditRowMissing;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Laravel\Audit\AuditExporter;
use Simtabi\Laranail\Impersonator\Laravel\Http\Requests\Api\ListAuditsRequest;
use Simtabi\Laranail\Impersonator\Laravel\Http\Resources\ImpersonationResource;
use Simtabi\Laranail\Impersonator\Laravel\Http\Resources\TrailEventResource;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Laravel\Services\AuditService;

/**
 * Reading the audit trail.
 *
 * Every response here goes through `ImpersonationResource`, which cannot emit a credential hash or a
 * session id — a listing is the likeliest place for a leak, because it is the endpoint people build
 * dashboards and CSV dumps on top of.
 *
 * Authorisation is on the Form Request for the list and re-checked per row for the detail views, so
 * a caller who can reach one impersonation cannot enumerate the rest.
 */
final readonly class AuditController
{
    public function __construct(
        private AuditService $audits,
        private AuditExporter $exporter,
    ) {}

    /** @return AnonymousResourceCollection<LengthAwarePaginator<int, ImpersonationAudit>> */
    public function index(ListAuditsRequest $request): AnonymousResourceCollection
    {
        $perPage = $request->integer('per_page') ?: null;

        $page = $this->audits->paginate($request->validated(), $perPage);

        // Mapped through the value object rather than serialising the model: the model carries the
        // credential hash and session id as attributes, and a resource over it would expose them the
        // first time somebody added a `$fillable`-style whitelist and forgot these two.
        return ImpersonationResource::collection(
            $page->through(static fn (ImpersonationAudit $row): ImpersonationSession => $row->toSession()),
        );
    }

    public function show(ListAuditsRequest $request, string $audit): JsonResponse
    {
        // 404 rather than letting AuditRowMissing escape: that exception means "state was lost
        // between opening a row and acting on it", which is a bug signal. An id typed by a client
        // that matches nothing is an ordinary not-found.
        $session = $this->audits->find($audit) ?? abort(404, 'No impersonation found for that id.');

        // The trail is paged even here: a long-running impersonation can have thousands of actions,
        // and returning them all would turn one request into an outage.
        $limit = min(max($request->integer('trail_limit') ?: 100, 1), 500);

        return ImpersonationResource::make($session)
            ->additional([
                'trail' => TrailEventResource::collection($this->audits->trail($audit, $limit)),
                'meta' => [
                    'trail_events' => $this->audits->trailCount($audit),
                    'trail_limit' => $limit,
                ],
            ])
            ->response();
    }

    /**
     * Export one impersonation and its full trail.
     *
     * Returned as a download rather than a JSON body: the caller is producing a document for a
     * compliance request, and a filename is part of what they need.
     */
    public function export(ListAuditsRequest $request, string $audit): Response
    {
        $format = $request->string('format', AuditExporter::JSON)->toString();

        if (! in_array($format, AuditExporter::formats(), true)) {
            $format = AuditExporter::JSON;
        }

        try {
            $document = $this->exporter->export($audit, $format);
        } catch (AuditRowMissing) {
            abort(404, 'No impersonation found for that id.');
        }

        return new Response($document, 200, [
            'Content-Type' => $format === AuditExporter::CSV ? 'text/csv' : 'application/json',
            'Content-Disposition' => sprintf(
                'attachment; filename="impersonation-%s.%s"',
                $audit,
                $format,
            ),
        ]);
    }
}
