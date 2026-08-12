<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Pagination\LengthAwarePaginator;
use Simtabi\Laranail\Impersonator\Core\Contracts\TrailStore;
use Simtabi\Laranail\Impersonator\Core\Values\ImpersonationSession;
use Simtabi\Laranail\Impersonator\Core\Values\TrailEvent;
use Simtabi\Laranail\Impersonator\Laravel\Models\ImpersonationAudit;
use Simtabi\Laranail\Impersonator\Laravel\Support\IdentityResolver;
use Simtabi\Laranail\Impersonator\Laravel\Support\Settings;

/**
 * Reading the audit trail: filtering, paging, and the trail of one impersonation.
 *
 * Separate from `AuditStore` on purpose. The store is the write path and the narrow set of lookups
 * the middleware needs on every request; this is the read path an operator or an auditor uses. They
 * have opposite constraints — the store must stay small and fast enough to run per-request, while
 * this is allowed to build arbitrary queries — and merging them would drag reporting concerns into
 * the hot path.
 *
 * Every filter is applied to the query rather than in PHP, because an audit table is the one table
 * that only grows and a year-old trail will not fit in memory.
 */
final readonly class AuditService
{
    public function __construct(
        private TrailStore $trail,
        private Settings $settings,
        private IdentityResolver $identities,
    ) {}

    /**
     * A filtered, paginated page of impersonations, newest first.
     *
     * The concrete paginator rather than the contract, deliberately: callers map the rows through
     * the value object with `through()`, which the interface does not declare. Returning the
     * interface would push every caller into serialising the Eloquent model instead — and the model
     * carries the credential hash and session id as attributes.
     *
     * @param array<string, mixed> $filters
     * @return LengthAwarePaginator<int, ImpersonationAudit>
     */
    public function paginate(array $filters = [], ?int $perPage = null): LengthAwarePaginator
    {
        $perPage = $this->resolvePerPage($perPage);

        return $this->query($filters)
            ->orderByDesc('started_at')
            ->orderByDesc('id')
            ->paginate($perPage)
            ->withQueryString();
    }

    /** @param array<string, mixed> $filters */
    public function count(array $filters = []): int
    {
        return $this->query($filters)->count();
    }

    public function find(string $auditId): ?ImpersonationSession
    {
        return ImpersonationAudit::query()->find($auditId)?->toSession();
    }

    /** @return list<TrailEvent> */
    public function trail(string $auditId, int $limit = 100, int $offset = 0): array
    {
        return $this->trail->forAudit($auditId, $limit, $offset);
    }

    public function trailCount(string $auditId): int
    {
        return $this->trail->countForAudit($auditId);
    }

    /**
     * @param array<string, mixed> $filters
     * @return Builder<ImpersonationAudit>
     */
    public function query(array $filters = []): Builder
    {
        $query = ImpersonationAudit::query();

        // Identity filters accept either `type:id` or a bare id. A bare id is matched on the id
        // column alone, which is what an operator pasting a user id from an admin screen means —
        // and the morph type is the part they are least likely to know.
        $this->applyIdentity($query, 'impersonator', $filters['impersonator'] ?? null);
        $this->applyIdentity($query, 'target', $filters['target'] ?? null);

        foreach (['tenant' => 'tenant_id', 'mode' => 'mode', 'driver' => 'driver', 'ended_by' => 'ended_by'] as $filter => $column) {
            $value = $filters[$filter] ?? null;

            if (is_string($value) && $value !== '') {
                $query->where($column, $value);
            }
        }

        if (array_key_exists('active', $filters) && $filters['active'] !== null) {
            $active = filter_var($filters['active'], FILTER_VALIDATE_BOOLEAN);

            $active ? $query->whereNull('ended_at') : $query->whereNotNull('ended_at');
        }

        // Bounded on `started_at` rather than `created_at`: an auditor asking "what happened last
        // Tuesday" means when the impersonation ran, and the two can differ.
        if (is_string($filters['from'] ?? null) && $filters['from'] !== '') {
            $query->where('started_at', '>=', $filters['from']);
        }

        if (is_string($filters['to'] ?? null) && $filters['to'] !== '') {
            $query->where('started_at', '<=', $filters['to']);
        }

        return $query;
    }

    /**
     * @param Builder<ImpersonationAudit> $query
     */
    private function applyIdentity(Builder $query, string $side, mixed $reference): void
    {
        if (! is_string($reference) || $reference === '') {
            return;
        }

        if (! str_contains($reference, ':')) {
            $query->where($side . '_id', $reference);

            return;
        }

        [$type, $id] = explode(':', $reference, 2);

        // The alias is resolved through the registry so a caller may pass either the alias or the
        // class name and get the same rows — the audit column holds whichever form was current when
        // the row was written. An unregistered type is matched verbatim rather than dropped, so a
        // filter on a model that has since been removed from the allowlist still finds its history.
        $resolved = $this->identities->typeFor($type);

        $query->where($side . '_type', $resolved === null ? $type : $resolved->alias)
            ->where($side . '_id', $id);
    }

    private function resolvePerPage(?int $requested): int
    {
        $default = $this->settings->int('api.per_page', 25);
        $max = $this->settings->int('api.max_per_page', 100);

        if ($requested === null || $requested < 1) {
            return min($default, $max);
        }

        // Clamped rather than rejected: a client asking for more than the cap gets the cap, which is
        // friendlier than a 422 and still bounds what one request can pull out of the audit table.
        return min($requested, $max);
    }
}
