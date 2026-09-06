# Security policy

## Supported versions

While the package is pre-1.0, security fixes land on the latest `0.x` release only.

| Version | Supported |
|---------|:---------:|
| `0.1.x` | Yes |

## Reporting a vulnerability

Report security issues privately to **security@simtabi.com**. Do not open a
public GitHub issue for a vulnerability.

Include, where you can: the affected version, a description of the issue, the
steps to reproduce it, and the impact you believe it has. A proof of concept
helps but is not required to report.

You can expect an acknowledgement within three working days and an assessment
within ten. Fixes for confirmed issues are released as a patch version, credited
to you unless you prefer otherwise.

> **Prefer GitHub private vulnerability reporting** when you can: open it from this
> repository's Security tab. The report arrives attached to the repo with a draft advisory
> and a CVE request path already in place. Email is the fallback for anyone who would
> rather not use GitHub.

## Scope

This package authenticates one user as another, so the following are always
treated as security issues rather than bugs:

- Any path that starts an impersonation without passing the authorization stack.
- Any way to change the active mode without leaving and re-entering.
- Any way to reach a third account from an impersonated session.
- Any leak of a handoff token or issued credential into a log, a response, an
  exception trace, or an audit row.
- Any way for the impersonator's own permissions to apply during impersonation.
- Any way to avoid, alter, or delete an audit row for an impersonation that
  happened.
- Any open redirect reachable through an accept, leave, or enter endpoint.

Findings that require an attacker to already hold the `impersonator.enter`
permission are in scope, since the whole point of the modes and the audit trail
is to constrain what an authorized operator can do unobserved.
