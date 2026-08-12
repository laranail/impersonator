## What this changes

<!-- One or two sentences. What behaviour is different after this merges? -->

## Why

<!-- The reason, not the mechanics. If it fixes an issue, link it. -->

## Security impact

Impersonation is a privilege-escalation surface, so this section is not optional.
Answer even when the answer is "none".

- [ ] Does this change who may impersonate, or what an impersonated session can do?
- [ ] Does it touch token generation, hashing, single-use redemption, or session regeneration?
- [ ] Could any credential, token, or hash now reach a log, a response, or an export?
- [ ] Does it add or relax a rule in `AuthorizationPolicy`, a `ModeEnforcer`, or the middleware?

## Checklist

- [ ] Tests cover the change, including the failing path — a control without a test proving it
      refuses is a control nobody has verified.
- [ ] `vendor/bin/pest` passes.
- [ ] `vendor/bin/phpstan analyse` is clean at level max.
- [ ] `vendor/bin/pint --test` and `vendor/bin/rector process --dry-run` are clean.
- [ ] `src/Core` still imports no `Illuminate` code (the layering test enforces this).
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]`.
- [ ] Docs updated if behaviour or configuration changed.
