# Changelog

All notable changes to `cboxdk/laravel-siem` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Development note

- `composer.json` carries a `path` repository pointing at `../siem` so the sibling
  `cboxdk/siem` core resolves from a local checkout during development, and the
  require is `dev-main as 0.1.0` (a `path` repo reports the working tree as
  `dev-main` and does not read git tags). **At release** this repository entry is
  removed and the constraint becomes a plain `^0.1` from Packagist.
  `cboxdk/laravel-ssrf` already resolves from Packagist and needs no path repo.

## [0.1.0] - 2026-07-15

### Added

- The SIEM delivery engine for Laravel, wrapping the framework-agnostic
  [`cboxdk/siem`](https://github.com/cboxdk/siem) event model and formatters.
- **Config registry** — `Contracts\LogStreams` + `DatabaseLogStreams`, and the
  tenancy-agnostic `Models\LogStream` (`log_streams`): destination enum, endpoint,
  an encrypted `secret` (reveal-once on create), an uninterpreted `owner_key` seam,
  action `filters`, per-field `redaction`, and circuit-breaker health columns.
  Deny-by-default: no enabled stream, nothing delivered.
- **Transactional outbox** — `Contracts\StreamDispatcher` + `DatabaseStreamDispatcher`
  and `Models\StreamDelivery` (`stream_deliveries`). `dispatch()` writes one cheap
  `pending` row per matching stream, inside the caller's transaction, so delivery is
  at-least-once. Applies the action filter before inserting.
- **Queued pump** — `Jobs\PumpStreamDeliveries` (per stream): triple-bounded
  batching (max records + max bytes + max age), redaction, core formatting, and
  delivery; on failure, bounded exponential backoff with jitter and a hard cap into
  a dead-letter that is never retried again.
- **Per-stream circuit breaker** — `Support\CircuitBreaker`: opens after N
  consecutive failures, pauses for a cooldown, half-open probe, closes on success.
  A failing stream never stops the app, the caller, or another stream, and failures
  are always counted (never black-holed). The failure count is reset only after a
  **fully** clean run, so a destination that fails a *later* batch each run still
  trips the breaker (a per-batch reset would let a partial failure be hammered
  forever).
- **One pump per stream** — `Jobs\PumpStreamDeliveries` is `ShouldBeUnique` keyed by
  the stream, so a slow destination can never let an overlapping scheduled run
  re-claim the same still-`pending` rows and multiply delivery to the customer's
  endpoint. Delivery stays at-least-once, not a self-amplifying duplicate storm.
- **Backpressure** — a bounded outbox with a configurable `drop_oldest` /
  `reject_new` policy that dead-letters shed rows, logs a warning, and fires
  `Events\OutboxOverflowed` as a metric hook.
- **HTTP sink** — `Sinks\HttpStreamSink` (implements the core `StreamSink`):
  SSRF-guarded and DNS-pinned via [`cboxdk/laravel-ssrf`](https://github.com/cboxdk/laravel-ssrf)
  (v4 + v6, redirects refused), TLS verification always on (no silent disable),
  per-destination framing and auth (Splunk HEC token, bearer, HMAC), optional gzip,
  and secret-scrubbed errors.
- **Redaction** — `Support\Redactor`: per-field hash/mask/drop applied before
  formatting, so a configured sensitive field never reaches the sink raw.
- **Fail-closed model resolution** — `Support\ModelClass::resolve()` centralizes the
  `config('siem.models.*')` lookup used by the registry, dispatcher, and pump. An
  unset key uses the base model (the standalone default); a valid subclass is used;
  **any other value throws** rather than silently falling back to the base. This
  matters because an isolation-sensitive host (e.g. laravel-id) swaps in an
  environment-owned subclass that shares the base table — a silent downgrade to the
  unscoped base would open the tenant boundary deployment-wide, so a misconfigured
  model is a hard error, never a guess.
- **Testing** — `Testing\{InteractsWithLogStreams, FakeStreamSink, FakeHttpTransport}`,
  dogfooded by the package's own Pest suite (deny-by-default, SSRF refusal, TLS-on,
  secret-at-rest, redaction, retry/dead-letter, circuit-breaker isolation, batching
  bounds, and at-least-once transaction framing).
- Publishable `config/siem.php` and migrations; a scheduled per-stream pump
  (toggle via `siem.schedule.enabled`).
