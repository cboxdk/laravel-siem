---
title: Quickstart
weight: 2
description: Install the package, register a stream, dispatch an event into the outbox, and let the queued pump deliver it.
---

# Quickstart

## 1. Install

```bash
composer require cboxdk/laravel-siem
```

The service provider is auto-discovered. Publish the migrations and (optionally)
the config:

```bash
php artisan vendor:publish --tag="siem-migrations"
php artisan vendor:publish --tag="siem-config"
php artisan migrate
```

This package encrypts destination secrets with Laravel's encrypter, so your app
needs an `APP_KEY` (any Laravel app already has one).

## 2. Register a stream

A `LogStream` is a configured destination. Register one through the `LogStreams`
registry — the endpoint is SSRF-checked before it is stored, and the secret is
revealed exactly once:

```php
use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Enums\Destination;

$registered = app(LogStreams::class)->create(
    name: 'splunk-prod',
    destination: Destination::SplunkHec,
    endpointUrl: 'https://http-inputs.example.splunkcloud.com',
    secret: 'your-hec-token',           // stored encrypted at rest
    redaction: ['password' => 'drop', 'email' => 'hash'],
    filters: ['allow' => ['user-login', 'role-granted']],
);
```

## 3. Dispatch an event into the outbox

Build a core `SiemEvent` and hand it to the `StreamDispatcher` **inside your own
database transaction**, so the outbox row commits atomically with your business
write:

```php
use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\Siem\ValueObjects\SiemEvent;
use Cbox\Siem\Enums\{EventCategory, Outcome, Severity};

DB::transaction(function () {
    // ... your business write ...

    $event = new SiemEvent(
        id: (string) Str::ulid(),
        occurredAt: new DateTimeImmutable(),
        action: 'user-login',
        category: EventCategory::Authentication,
        outcome: Outcome::Success,
        severity: Severity::Info,
    );

    app(StreamDispatcher::class)->dispatch($event, app(LogStreams::class)->enabled());
});
```

`dispatch()` writes one cheap `pending` row per matching stream. Nothing goes over
the network yet.

## 4. Deliver

By default the package registers a scheduled task that, every minute, dispatches a
per-stream pump job onto the queue. Just run a worker and the scheduler:

```bash
php artisan queue:work
php artisan schedule:work
```

The pump claims due rows, batches them, redacts, formats with the destination's
core formatter, and ships them over SSRF-guarded HTTPS. To drive it yourself
instead, set `siem.schedule.enabled = false` and dispatch
`Cbox\LaravelSiem\Jobs\PumpStreamDeliveries::dispatch($streamId)`.

## Testing

Compose `InteractsWithLogStreams` into your `TestCase` to run the whole pipeline in
memory with no network — see [custom sink](extension-points/custom-sink.md) and the
`FakeStreamSink`.
