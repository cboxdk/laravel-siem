# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities through GitHub's
[Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (the **Security** tab → **Report a vulnerability**).

Please do not open a public issue for a suspected vulnerability. We will
acknowledge your report and work with you on a fix and coordinated disclosure on
a best-effort basis.

## Scope

This package is the **delivery layer** over the framework-agnostic
[`cboxdk/siem`](https://github.com/cboxdk/siem) event model and formatters. It
owns HTTP egress, the durable outbox, queued batched delivery, encrypted
destination secrets, and PII redaction.

The event schema and its own injection posture — CEF/CRLF neutralization, field
spoofing, and the escaping rules for each formatter — live in `cboxdk/siem`.
Report issues in that behaviour against the
[`cboxdk/siem`](https://github.com/cboxdk/siem) repository; report issues in the
delivery layer (egress guarding, secret handling, redaction, retry/circuit
behaviour) here. The SSRF guard itself is
[`cboxdk/laravel-ssrf`](https://github.com/cboxdk/laravel-ssrf) — report
guard-specific issues there.

## Security Posture

- **SSRF-guarded egress.** Every outbound request is validated and DNS-pinned via
  `cboxdk/laravel-ssrf`, at both stream registration and every delivery, with
  redirects refused. Enforcement can be disabled (`siem.http.verify_url`) only for
  single-tenant on-prem installs reaching an internal collector; keep it on in any
  multi-tenant deployment.
- **TLS verification is always on** and cannot be disabled silently. Setting
  `siem.http.tls_verify = false` logs a loud warning on every send.
- **Secrets are encrypted at rest** (Laravel `encrypted` cast), revealed once on
  creation, and scrubbed from every stored error and dead-letter payload.
- **PII redaction** (hash/mask/drop) is applied per field before formatting, so a
  configured sensitive field is never streamed raw.

See [`docs/security/`](docs/security/_index.md) for the full posture.
