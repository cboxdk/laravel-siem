---
title: Stream to Elastic
weight: 2
description: Configure an Elastic (ECS) stream — ECS-shaped JSON documents delivered over HTTP with a bearer token.
---

# Stream to Elastic (ECS)

## Register the stream

```php
use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Enums\{AuthScheme, Destination};

app(LogStreams::class)->create(
    name: 'elastic-audit',
    destination: Destination::ElasticEcs,
    endpointUrl: 'https://ingest.example.elastic-cloud.com/_bulk-ish-endpoint',
    secret: 'YOUR-API-KEY',
    auth: AuthScheme::Bearer,   // Authorization: Bearer <secret>
);
```

## What the sink sends

- **Body** — each event as an [Elastic Common Schema](https://github.com/cboxdk/siem)
  document (`@timestamp`, `event.kind`/`category`/`type`/`outcome`, `ecs.version`,
  `log.level`, `labels.*`), newline-delimited (NDJSON).
- **Auth** — a bearer token by default; switch to `AuthScheme::Hmac` for an
  HMAC-SHA256 signature over `timestamp.body` (headers `X-Cbox-Timestamp` /
  `X-Cbox-Signature`) when the collector verifies signatures instead.

## Graylog and generic JSON

The same pattern applies to `Destination::GraylogGelf` (GELF 1.1 over HTTP — never
UDP, so audit data is never silently dropped) and `Destination::GenericJson` (the
neutral single-line JSON formatter) and `Destination::CefHttp` (ArcSight/syslog CEF
lines). Only the formatter and default framing differ; the delivery guarantees are
identical.
