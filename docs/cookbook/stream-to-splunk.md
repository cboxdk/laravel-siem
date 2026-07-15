---
title: Stream to Splunk
weight: 1
description: Configure a Splunk HTTP Event Collector (HEC) stream — token auth, the collector event endpoint, and NDJSON framing.
---

# Stream to Splunk (HEC)

## Register the stream

```php
use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Enums\Destination;

app(LogStreams::class)->create(
    name: 'splunk-prod',
    destination: Destination::SplunkHec,
    endpointUrl: 'https://http-inputs.example.splunkcloud.com',
    secret: 'YOUR-HEC-TOKEN',   // stored encrypted; revealed once on the return value
);
```

## What the sink sends

- **Endpoint** — when you give a bare host (no path), the sink posts to
  `…/services/collector/event`, the HEC endpoint for structured events. Give a full
  path and it is used verbatim.
- **Auth** — `Authorization: Splunk <token>` (the HEC scheme). The token is only
  ever a header; it is never logged and never appears in a stored error.
- **Body** — the [`SplunkHecFormatter`](https://github.com/cboxdk/siem) envelopes
  (with an epoch-seconds `time`), newline-concatenated into one NDJSON request —
  which is exactly how HEC accepts a batch.

## Tuning

- Batch size: `SIEM_BATCH_MAX_RECORDS`, `SIEM_BATCH_MAX_BYTES`.
- Compression: set `SIEM_GZIP=true` to gzip the request body.
- The `sourcetype` defaults to `cbox:siem` (from the core formatter).
