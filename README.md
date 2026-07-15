# Cbox SIEM for Laravel

[![Latest Version on Packagist](https://img.shields.io/packagist/v/cboxdk/laravel-siem.svg?style=flat-square)](https://packagist.org/packages/cboxdk/laravel-siem)
[![Total Downloads](https://img.shields.io/packagist/dt/cboxdk/laravel-siem.svg?style=flat-square)](https://packagist.org/packages/cboxdk/laravel-siem)
![PHP Version](https://img.shields.io/packagist/php-v/cboxdk/laravel-siem?style=flat-square)

The SIEM log-streaming **delivery engine** for Laravel: a durable transactional
outbox, queued batched delivery with retry, dead-letter, and a per-stream circuit
breaker, SSRF-guarded HTTP egress, encrypted destination secrets, and per-field PII
redaction — shipping normalized security events to Splunk HEC, Elastic (ECS),
Graylog (GELF), ArcSight/syslog (CEF), or any HTTP JSON collector.

This package is the **Laravel wrapper** over the framework-agnostic
[`cboxdk/siem`](https://github.com/cboxdk/siem) core. The core owns the event model
and the formatters (the *shape* of the data); this package owns *delivery* (the
network, the durability, the secrets). An audit binding in
[`cboxdk/laravel-id`](https://github.com/cboxdk/laravel-id) consumes this layer to
stream a tamper-evident audit trail — that binding is a separate package.

## Installation

```bash
composer require cboxdk/laravel-siem

php artisan vendor:publish --tag="siem-migrations"
php artisan vendor:publish --tag="siem-config"   # optional
php artisan migrate
```

The service provider is auto-discovered. Destination secrets use Laravel's
encrypter, so an `APP_KEY` is required (every Laravel app has one).

## At a glance

```php
use Cbox\LaravelSiem\Contracts\{LogStreams, StreamDispatcher};
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\Siem\ValueObjects\SiemEvent;

// 1. Register a destination (endpoint SSRF-checked; secret encrypted, revealed once).
app(LogStreams::class)->create(
    name: 'splunk-prod',
    destination: Destination::SplunkHec,
    endpointUrl: 'https://http-inputs.example.splunkcloud.com',
    secret: 'your-hec-token',
    redaction: ['password' => 'drop', 'email' => 'hash'],
);

// 2. In your own DB transaction, write the event to the outbox (a cheap insert).
DB::transaction(function () use ($event) {
    // ... your business write ...
    app(StreamDispatcher::class)->dispatch($event, app(LogStreams::class)->enabled());
});

// 3. The queued pump batches, redacts, formats, and ships it — off the request thread.
```

## What it guarantees

- **Deny-by-default** — no enabled stream, nothing delivered.
- **At-least-once, unordered** — the outbox row commits in your transaction; a
  rolled-back caller leaves no orphan. Duplicates are possible; dedup by event id.
- **Never blocks the request** — all delivery is queued.
- **Bounded everything** — triple-bounded batches (records/bytes/age), bounded
  exponential backoff with jitter, a hard retry cap into a dead-letter, a bounded
  outbox with an explicit backpressure policy, and a per-stream circuit breaker.
- **Safe egress** — SSRF-guarded and DNS-pinned, TLS verification always on,
  secrets encrypted at rest and scrubbed from logs, PII redacted before formatting.

## Destinations

| Destination | SIEM | Framing |
|-------------|------|---------|
| `splunk_hec` | Splunk HEC | NDJSON to the collector event endpoint, `Authorization: Splunk <token>` |
| `elastic_ecs` | Elastic / Kibana | ECS JSON documents (NDJSON) |
| `graylog_gelf` | Graylog | GELF 1.1 over HTTP (never UDP) |
| `cef_http` | ArcSight / syslog | CEF lines over HTTP |
| `generic_json` | any HTTP collector | neutral single-line JSON |

## Testing

Compose `Cbox\LaravelSiem\Testing\InteractsWithLogStreams` into your `TestCase` to
run the whole pipeline in memory: `fakeStreamSink()` binds an in-memory
`FakeStreamSink`, `createLogStream(...)` registers through the real registry, and
`pumpStream($id)` runs a delivery cycle synchronously. `FakeHttpTransport` programs
the HTTP fake for testing the real `HttpStreamSink`.

## Requirements

- PHP 8.4+
- Laravel 12.x or 13.x
- A queue connection, a database, and an `APP_KEY`.

## Documentation

Full documentation lives in [`docs/`](docs/index.md).

## The event core

The normalized `SiemEvent`, the formatters, and their escaping/threat model are
provided by [`cboxdk/siem`](https://github.com/cboxdk/siem). This package claims
only the Laravel delivery layer.

## Credits

- [Sylvester Damgaard](https://github.com/cboxdk)

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
