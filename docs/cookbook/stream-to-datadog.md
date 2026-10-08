---
title: Stream to Datadog
weight: 3
description: Configure a Datadog Logs stream — API key, site, service/source/tags, and the intake's request limits.
---

# Stream to Datadog

## Set up Datadog

1. **Organization Settings → API Keys → New Key.** Use an *API key*, not an
   application key.
2. Note your **site** — the domain of the Datadog URL you sign in to. A key only
   works against its own site.

| Site | Option value | Intake |
|------|--------------|--------|
| US1 | `datadoghq.com` | `https://http-intake.logs.datadoghq.com/api/v2/logs` |
| US3 | `us3.datadoghq.com` | `https://http-intake.logs.us3.datadoghq.com/api/v2/logs` |
| US5 | `us5.datadoghq.com` | `https://http-intake.logs.us5.datadoghq.com/api/v2/logs` |
| EU1 | `datadoghq.eu` | `https://http-intake.logs.datadoghq.eu/api/v2/logs` |
| AP1 | `ap1.datadoghq.com` | `https://http-intake.logs.ap1.datadoghq.com/api/v2/logs` |
| AP2 | `ap2.datadoghq.com` | `https://http-intake.logs.ap2.datadoghq.com/api/v2/logs` |
| US1-FED | `ddog-gov.com` | `https://http-intake.logs.ddog-gov.com/api/v2/logs` |

## Register the stream

```php
use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Enums\Destination;

app(LogStreams::class)->create(
    name: 'datadog',
    destination: Destination::Datadog,
    endpointUrl: '',                       // derived from the site
    secret: 'your-datadog-api-key',        // stored encrypted
    options: [
        'site' => 'datadoghq.eu',
        'service' => 'my-app',
        'source' => 'cbox',
        'tags' => ['env:prod', 'team:security'],
        'hostname' => 'id.example.com',
    ],
);
```

Every option but `site` is optional: `service` defaults to `siem.datadog.service`
or `app.name`, `source` to `siem.datadog.source` (`cbox`), and `hostname` to the
host of `app.url`. Pass an `https://` `endpointUrl` only to go through a proxy (a bare
host gets `/api/v2/logs` appended); it is SSRF-checked like any endpoint.

## What the sink sends

- `POST` to the site's intake, `Content-Encoding: gzip`, `DD-API-KEY: <key>` — the
  key is a header, never in the URL, and is scrubbed from every stored error.
- A JSON array of entries: `ddsource`, `ddtags`, `hostname`, `service`, and
  `message` — the event as the neutral single-line JSON document, which Datadog
  parses into attributes.
- **Limits** — at most 1000 entries and 5 MB of uncompressed JSON per request. The
  pump cuts batches to these limits whatever `siem.batch` says, and the sink splits
  defensively too.

## Failures

A 401/403 (a wrong, revoked or other-site key) opens the stream's circuit at once
and marks it `action_required`; see [stream health](../core-concepts/stream-health.md).
408, 429 and 5xx are retried with backoff.
