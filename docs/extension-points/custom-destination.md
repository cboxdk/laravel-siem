---
title: Custom destination
weight: 2
description: How destinations map to core formatters, and how to extend the models and the registry through config.
---

# Custom destination

## Destinations map to core formatters

`Cbox\LaravelSiem\Enums\Destination` selects the pure formatter and the sink's
framing/auth defaults:

| Destination | Core formatter | Default auth |
|-------------|----------------|--------------|
| `SplunkHec` | `SplunkHecFormatter` | Splunk token |
| `ElasticEcs` | `EcsFormatter` | Bearer |
| `GraylogGelf` | `GelfFormatter` | Bearer |
| `CefHttp` | `CefFormatter` | Bearer |
| `GenericJson` | `JsonFormatter` | Bearer |
| `Datadog` | `JsonFormatter` (as each entry's `message`) | none — `DD-API-KEY` |
| `S3` | `JsonFormatter` (one NDJSON line per event) | none — AWS SigV4 |
| `Gcs` | `JsonFormatter` (one NDJSON line per event) | none — Google OAuth token |

The last three take typed `options` (`Destination::requiresOptions()`), validated by
`Support\DestinationSettings` into `ValueObjects\Options\{DatadogOptions,
S3Options, GcsOptions}` before the registry stores them.

To add a genuinely new SIEM schema, add the pure formatter to the
[`cboxdk/siem`](https://github.com/cboxdk/siem) core (that is where formatting
lives), then extend `FormatterFactory` — or, more simply, rebind the sink (see
[custom sink](custom-sink.md)) if only the transport differs.

## Extend the models

The models are resolved through `config('siem.models')`, so a host can subclass
them (e.g. to add a tenant scope) while the package still owns the schema:

```php
// config/siem.php
'models' => [
    'log_stream' => App\Models\TenantLogStream::class,
    'stream_delivery' => Cbox\LaravelSiem\Models\StreamDelivery::class,
],
```

`LogStream` carries an uninterpreted `owner_key` for exactly this — the package
never assigns it meaning, so a host scopes streams by environment/org/team by
filtering on it (`LogStreams::enabled($ownerKey)`) without this package assuming a
tenancy model.

## Replace the registry

`Cbox\LaravelSiem\Contracts\LogStreams` is bound to `DatabaseLogStreams`. Rebind it
to source streams from somewhere else (a config file, a control-plane API) while
keeping the same dispatcher and pump.
