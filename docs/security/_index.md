---
title: Security
weight: 7
description: The delivery layer's security posture — SSRF-guarded egress, TLS verification, encrypted secrets, and PII redaction.
---

# Security

This layer is where the network and the secrets live, so it is where the egress
footguns are closed.

- [Egress, SSRF, and secrets](egress-ssrf-and-secrets.md) — how outbound requests
  are guarded, why TLS verification cannot be silently disabled, and how
  destination secrets are protected at rest and in logs.
- [Redaction](redaction.md) — per-field PII redaction applied before an event is
  formatted.

The event model's own escaping and injection posture (CEF/CRLF neutralization,
field spoofing) is documented in [`cboxdk/siem`](https://github.com/cboxdk/siem).
