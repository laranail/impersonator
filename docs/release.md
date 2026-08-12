# Release

How a version of this package is cut.

## Versioning

Semantic versioning. While pre-1.0 the laranail family keeps **one `v0.1.0` tag per repository and
moves it** on each change, rather than cutting new patch versions — consumers on `^0.1` pick up
the moved tag on their next `composer update`. History stays a single `Initial release` commit
until the family stabilises.

## Inter-package resolution

laranail packages resolve each other through **git VCS repositories, not Packagist**. This package
currently has no `laranail/*` dependencies, so there is nothing to declare — but a consumer adding
it alongside other laranail packages should add the VCS repository rather than rely on Packagist:

```json
{
  "repositories": [
    { "type": "vcs", "url": "https://github.com/laranail/impersonator" }
  ]
}
```

## No lock file

`composer.lock` is untracked and git-ignored. In a library a lock records a resolution consumers
never use, and it goes stale invisibly because CI resolves fresh. Do not run
`composer update --lock` to quiet `composer validate --strict`; CI passes `--no-check-lock`
instead.

## Dependency constraints

Never pinned to an exact version. Range constraints only — `^8.3`, `^13.0`. Raising a *floor* to
exclude a known-broken release is not a pin and is fine.

## What CI gates

Every push and pull request runs:

| Workflow | Job | Gate |
|---|---|---|
| `tests.yml` | `test` | PHP 8.3/8.4/8.5 × Laravel 13, plus one `prefer-lowest` run on the floor |
| `tests.yml` | `test-without-optional` | The suite with Sanctum, Passport, JWT and stancl removed |
| `tests.yml` | `boot-health` | Nothing degraded during a normal boot |
| `static-analysis.yml` | `phpstan` | Level max, no baseline, no ignores |
| `static-analysis.yml` | `style` | `pint --test` |
| `static-analysis.yml` | `rector` | `rector --dry-run` |
| `static-analysis.yml` | `architecture` | `src/Core` imports no `Illuminate` code |
| `static-analysis.yml` | `composer-validate` | `composer validate --strict --no-check-lock` |

The `test-without-optional` job is the one that matters for the dependency contract. Installing
the optional packages in every job would hide a hard dependency that had crept into a driver or
the service provider, and the first person to find it would be a user who does not have Passport
installed. That job also asserts the packages really are absent, so it cannot pass while testing
the wrong thing.

The `boot-health` job exists because a degradable registration that silently failed leaves an
application that starts cleanly and quietly lacks a feature — which no functional test catches.

## Release checklist

1. `CHANGELOG.md` — move `## [Unreleased]` entries under the new version with a date.
2. Run the full local sweep: `pest`, `phpstan analyse`, `pint --test`, `rector --dry-run`.
3. Run `php artisan laranail::impersonator.doctor` in a scratch application.
4. Confirm CI is green on `main`.
5. Tag, and push the tag.

Every GitHub release carries a human-readable description sourced from that version's CHANGELOG
section — never auto-generated notes alone, and never a bare "see CHANGELOG" stub.

## Security releases

A fix for a reported vulnerability ships as its own release with no unrelated changes, so
consumers can upgrade without evaluating anything else. Disclosure follows
[SECURITY.md](../SECURITY.md).

---

[← Docs index](../README.md#documentation)
