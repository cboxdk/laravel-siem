---
title: Egress, SSRF, and secrets
weight: 1
description: SSRF-guarded, DNS-pinned HTTP egress with TLS verification always on, and destination secrets encrypted at rest and scrubbed from logs.
---

# Egress, SSRF, and secrets

## SSRF-guarded egress

Every outbound request goes through
[`cboxdk/laravel-ssrf`](https://github.com/cboxdk/laravel-ssrf), the same
independently-tested guard the rest of the platform uses. It refuses any endpoint
that resolves to a non-public address — loopback, RFC-1918 private, link-local, ULA,
CGNAT (100.64/10), TEST-NET, multicast, and cloud metadata (`169.254.169.254`,
IPv6 `fd00:ec2::254`) — for **both IPv4 and IPv6**, and blocks disallowed schemes
and embedded credentials.

The guard runs at **two points**:

1. **Registration** — `LogStreams::create()` refuses to store a stream whose
   endpoint is unsafe.
2. **Every delivery** — the sink re-validates and **pins** the connection to the
   exact IPs it just resolved (`CURLOPT_RESOLVE` + a post-connect peer check) and
   **refuses redirects**. This closes the DNS-rebinding TOCTOU window: a hostname
   that passed validation cannot be re-pointed at an internal address between the
   check and the connect, and a `30x` to an internal host is never followed.

A blocked endpoint aborts the send before any bytes leave; the delivery is then
retried/dead-lettered like any other failure.

For a single-tenant on-prem install that must reach an internal collector, set
`siem.http.verify_url = false` to disable enforcement. **This turns off the entire
guard — not just IP pinning but also the scheme allow-list and the
credentials-in-URL rejection** — and lets a stream point anywhere, so it is only
ever appropriate for a single-tenant box where the operator controls every
destination. Keep it **on** in any multi-tenant deployment: a host that lets
different tenants configure their own stream endpoints (as the laravel-id audit
binding does) must never expose this toggle to them, or one tenant could aim a
stream at an internal service or the cloud metadata endpoint.

### Cloud destinations

The Datadog, S3 and GCS sinks and the credential exchanges (STS `AssumeRole`, the
Google token request) go through the same egress path: the **exact request URL**
(for S3, the virtual-hosted bucket host) is validated and pinned on every request. A
custom endpoint (MinIO, R2, a Datadog proxy) is checked at registration too, and must
be `https://`. The Google token endpoint is `siem.gcs.token_uri`, never the
`token_uri` inside a customer's key file, so a crafted key cannot redirect it.

## TLS verification is always on

Certificate verification is never disabled silently. The sink adds no `verify`
option by default, so Guzzle's default (verification **on**) stands. The only way to
turn it off is `siem.http.tls_verify = false`, and doing so logs a loud warning on
**every** send. Never disable it in production.

## Secrets at rest and in logs

- **At rest** — a stream's `secret` (HEC token, bearer token, or HMAC key) is
  stored with Laravel's `encrypted` cast. The raw database column is ciphertext; the
  plaintext exists only in memory at delivery time.
- **Revealed once** — `create()` returns the plaintext exactly once (a generated
  HMAC key, or a caller-supplied token echoed back). After that it is unrecoverable
  from the model.
- **Cloud credentials** — the Datadog API key, the S3 secret access key and the GCS
  service-account JSON key are the same encrypted `secret`; non-secret settings
  (site, bucket, region, access key ID, role ARN, external ID) live in `options`.
  Short-lived credentials derived from them (GCS access tokens, STS session
  credentials) are cached encrypted with the app key and expire early. Assumed-role
  S3 streams store no customer secret at all, and each gets its own external ID.
- **Never logged** — the token is only ever a request header or an HMAC input.
  Every stored delivery error and dead-letter payload is passed through a scrubber
  that strips the secret, so it can never leak into `last_error`.
