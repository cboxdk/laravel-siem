# Changelog

All notable changes to `cboxdk/laravel-siem` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-08

### Added

- **Datadog destination** (`Destination::Datadog`) — the Logs intake API v2 on any
  Datadog site (`DatadogSite`: US1/US3/US5/EU1/AP1/AP2/US1-FED). Entries carry
  `ddsource`, `service`, `ddtags`, `hostname` and the event JSON as `message`; gzip;
  the API key in `DD-API-KEY`. Requests never exceed the intake's 1000 entries /
  5 MB uncompressed, whatever `siem.batch` says (the pump clamps to
  `Destination::maxBatchRecords()`/`maxBatchBytes()`, and the sink splits).
- **Amazon S3 destination** (`Destination::S3`) — one NDJSON object per batch under
  `{prefix}/{yyyy}/{mm}/{dd}/{hh}/{batch-id}.ndjson[.gz]`, signed with AWS Signature
  V4 (`Support\Aws\SigV4Signer`, verified against AWS's published test vectors — no
  AWS SDK dependency). Access-key or **assumed-role** credentials (STS `AssumeRole`
  with the platform's identity from `siem.aws.*` and a generated per-stream external
  ID; temporary credentials cached encrypted), optional SSE (`AES256` / `aws:kms`),
  and S3-compatible endpoints (MinIO, R2) with path-style addressing.
- **Google Cloud Storage destination** (`Destination::Gcs`) — the same object
  layout, authorized by a service-account JSON key: an RS256 JWT (OpenSSL) exchanged
  for an access token (RFC 7523), cached encrypted. The key file's own `token_uri`
  is ignored in favour of `siem.gcs.token_uri`.
- **Typed destination options** — a nullable `options` JSON column on
  `log_streams`, validated by `Support\DestinationSettings` into
  `ValueObjects\Options\{DatadogOptions, S3Options, GcsOptions}`;
  `LogStreams::create()` gains an optional trailing `array $options = []`.
  Invalid settings throw `Exceptions\InvalidStreamConfiguration` (with the field
  name) before anything is stored. An empty endpoint means the destination's own;
  a custom one must be `https` and passes the SSRF guard.
- **Refusals vs transient failures** — `Exceptions\DestinationRefused`
  (a `StreamDeliveryFailed` with a `FailureKind`: authentication / configuration).
  The pump opens the circuit at once on a refusal and keeps the rows pending without
  spending their retry budget; `LogStreams::update()` of the destination settings
  re-validates them and resets the breaker.
- **Stream status** — `last_error`, `last_failure_kind`, `last_failure_at` columns;
  `LogStream::health()` / `CircuitBreaker::health()` → `StreamHealth`
  (healthy / degraded / paused / action_required).
- **Test delivery** — `Contracts\StreamTester` (default `SinkStreamTester`) sends one
  marked `siem.stream.test` event synchronously and returns a `TestDeliveryResult`;
  a success also closes the breaker.
- `Sinks\DestinationRouter` (the new `StreamSink` binding) routing to
  `HttpStreamSink`, `DatadogStreamSink`, `S3StreamSink`, `GcsStreamSink`; the shared
  `Support\Egress` path (SSRF pin, TLS, timeouts, scrubbing) every sink and
  credential exchange uses; rebindable `Contracts\AwsCredentialResolver` and
  `Contracts\GcsAccessTokens`.
- `Destination::httpCollectors()` / `requiresOptions()` / `isObjectStorage()`, so a
  host whose form collects only a URL and a token can keep offering exactly the
  original five.
- Testing: `FakeStreamSink::refuseFor()` / `acceptAgain()`,
  `FakeHttpTransport::refusingCredentials()`, `InteractsWithLogStreams::testLogStream()`
  and an `$options` argument on `createLogStream()`.
- Migration `2026_10_08_000100_add_destination_options_to_log_streams` — nullable
  columns, no defaults, each added only if missing (safe to re-run).
- `ext-openssl` is now an explicit requirement (it signs the GCS token request).

### Changed

- The HTTP collectors map **401/403 to a refusal** too: a Splunk/Elastic/… stream
  whose token is rejected now opens its circuit immediately and shows
  `action_required`, instead of retrying the same token until the rows dead-letter.
- `SecretScrubber::scrubAll()` scrubs several secrets (longest first); every secret
  parameter is marked `#[SensitiveParameter]`.
- The committed `sbom.json` is regenerated against current dependency versions.

## [0.1.1] - 2026-07-15

### Fixed

- **Installable from Packagist.** v0.1.0 shipped with the dev-only composer wiring
  still in place — a `path` repository to `../siem` and `"cboxdk/siem": "dev-main as
  0.1.0"` — so a plain `composer require cboxdk/laravel-siem` could not resolve the
  core (`dev-main` is not a Packagist version). The `path` repository is removed and
  the require is now `"cboxdk/siem": "^0.1"` from Packagist. No code changed; the
  full gate is green against the published `cboxdk/siem` v0.1.0.

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
