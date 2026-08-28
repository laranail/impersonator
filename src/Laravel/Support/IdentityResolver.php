<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\SoftDeletingScope;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Contracts\Config\Repository as Config;
use Simtabi\Laranail\Impersonator\Core\Values\Identity;
use Simtabi\Laranail\Impersonator\Core\Exceptions\InvalidIdentity;

/**
 * Translates between application users and the Core layer's Identity value.
 *
 * This is the one place a class name from outside becomes a loadable model, so
 * it is also where the allowlist is enforced. Everything about the direction of
 * the checks here is deliberate: an unlisted class resolves to nothing rather
 * than to a model, and an empty allowlist denies every target rather than
 * permitting any.
 */
final readonly class IdentityResolver
{
    public function __construct(
        private Config $config,
        private TargetRegistry $targets,
    ) {}

    /**
     * Reduce a user model to its audit-stable (type, id) pair.
     *
     * `type` prefers the morph alias so the audit row survives a class being
     * moved or renamed — the row has to stay resolvable years after it was
     * written, and a fully-qualified class name is the part of an application
     * most likely to have moved by then.
     */
    public function fromUser(Authenticatable|Model $user): Identity
    {
        $class = $user instanceof Model ? $user->getMorphClass() : $user::class;
        $key = $user instanceof Model ? $user->getKey() : $user->getAuthIdentifier();

        if (! is_int($key) && ! is_string($key)) {
            // An unsaved model, or one keyed by something an audit row cannot
            // store and later resolve. Failing here beats writing a row that
            // points at nothing.
            throw InvalidIdentity::unusableKey($class, get_debug_type($key));
        }

        return new Identity(
            type: $this->aliasFor($class),
            id: $key,
            label: $this->labelFor($user),
        );
    }

    /**
     * Load the model an Identity refers to, or null.
     *
     * Returns null for a type outside the allowlist without touching the
     * database. That ordering is the control: resolving first and checking
     * afterwards would already have let a caller name an arbitrary model and
     * have it loaded.
     */
    public function toUser(Identity $identity, bool $withTrashed = false): ?Model
    {
        $class = $this->classFor($identity->type);

        if ($class === null) {
            return null;
        }

        $model = new $class;
        $query = $model->newQuery();

        // Lifting the scope directly rather than calling `withTrashed()`, which
        // is a builder macro: macros are invisible to both method_exists() and
        // static analysis, so calling one here could only be reached by
        // suppressing the very check that would catch it going wrong.
        if ($withTrashed && $this->usesSoftDeletes($model)) {
            $query->withoutGlobalScope(SoftDeletingScope::class);
        }

        return $query->find($identity->id);
    }

    /** Build an Identity from validated request input. */
    public function identity(string $type, int|string $id, ?string $label = null): Identity
    {
        return new Identity($type, $id, $label);
    }

    /**
     * Resolve an operator — the impersonator side — without the target allowlist.
     *
     * The asymmetry is deliberate, and getting it wrong is a real footgun. `targets.allowlist`
     * exists to stop an attacker-supplied class name becoming a loaded model, and it applies
     * to the target because the target arrives as request input. An impersonator's identity
     * comes from the authenticated session or from a server-written audit row, so it is not
     * the same threat — and requiring operators to be listed would force an `Admin` model
     * that enters as `User` into a list of accounts that may be *impersonated*, which is
     * exactly backwards.
     *
     * Still constrained: the type must resolve to an installed Eloquent model, either through
     * the allowlist, a registered morph map, or a real class name.
     */
    public function resolveActor(Identity $identity): ?Model
    {
        $class = $this->classFor($identity->type)
            ?? $this->morphMapClass($identity->type)
            ?? $this->modelClass($identity->type);

        if ($class === null) {
            return null;
        }

        $model = new $class;

        // Operators are resolved with trashed rows included: an account deactivated since
        // the impersonation began must still be nameable in the audit trail, or the record
        // stops describing who acted.
        $query = $model->newQuery();

        if ($this->usesSoftDeletes($model)) {
            $query->withoutGlobalScope(SoftDeletingScope::class);
        }

        return $query->find($identity->id);
    }

    /** Whether a class or morph alias may be impersonated at all. */
    public function isAllowlisted(string $typeOrClass): bool
    {
        return $this->classFor($typeOrClass) !== null;
    }

    /**
     * The class a registered type maps to, or null when it is not registered.
     * Accepts either the alias or the class itself, so callers do not have to know which
     * form they were handed.
     *
     * @return class-string<Model>|null
     */
    public function classFor(string $typeOrClass): ?string
    {
        return $this->targets->find($typeOrClass)?->model;
    }

    /** The alias a registered class maps to, falling back to the class name. */
    public function aliasFor(string $class): string
    {
        $type = $this->targets->find($class);

        // `class => class` is how a bare list entry normalises, and it is not an alias.
        // Returning it would shadow a morph map the application registered globally,
        // giving one type two spellings across its audit rows.
        if ($type !== null && $type->alias !== $class) {
            return $type->alias;
        }

        $morphMap = array_search($class, Relation::morphMap(), true);

        return is_string($morphMap) ? $morphMap : $class;
    }

    /** The registered type for an alias or class, or null. */
    public function typeFor(string $aliasOrClass): ?ImpersonatableType
    {
        return $this->targets->find($aliasOrClass);
    }

    public function targets(): TargetRegistry
    {
        return $this->targets;
    }

    /**
     * The impersonatable types, alias => class.
     *
     * Delegates to the registry, which merges config with any types registered at runtime
     * and validates each is an installed Eloquent model — so a typo or a stale entry
     * narrows the list rather than becoming a crash on an unrelated request. An empty
     * result denies every target, the correct direction for this list to fail in.
     *
     * @return array<string, class-string<Model>>
     */
    public function allowlist(): array
    {
        return $this->targets->map();
    }

    public function usesSoftDeletes(Model $model): bool
    {
        return in_array(SoftDeletes::class, class_uses_recursive($model), true);
    }

    /**
     * Whether the given model is currently soft-deleted.
     *
     * False for a model that does not soft-delete at all, so the caller can ask
     * this unconditionally — the soft-delete refusal applies to every target,
     * and a policy that had to know which models support it would get it wrong.
     */
    public function isTrashed(Model $model): bool
    {
        return method_exists($model, 'trashed') && $model->trashed() === true;
    }

    /** @return class-string<Model>|null */
    private function morphMapClass(string $type): ?string
    {
        $class = Relation::morphMap()[$type] ?? null;

        return is_string($class) && is_subclass_of($class, Model::class) ? $class : null;
    }

    /** @return class-string<Model>|null */
    private function modelClass(string $type): ?string
    {
        return is_subclass_of($type, Model::class) ? $type : null;
    }

    /**
     * The label to record for a user.
     *
     * Prefers the attribute the *type* declares, because `name` is not universal — a
     * vendor may be `company_name` and a customer `full_name`, and a single global
     * setting cannot describe both. Falls back to the global one.
     */
    private function labelFor(Authenticatable|Model $user): ?string
    {
        if (! $user instanceof Model) {
            return null;
        }

        $declared = $this->targets->forModel($user)?->displayName;

        $attribute = $declared ?? $this->config->get('laranail.impersonator.banner.display_name', 'name');

        if (! is_string($attribute) || $attribute === '') {
            return null;
        }

        $value = $user->getAttribute($attribute);

        return is_scalar($value) ? (string) $value : null;
    }
}
