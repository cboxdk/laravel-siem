# Cbox SIEM for Laravel

[![Latest Version on Packagist](https://img.shields.io/packagist/v/cboxdk/laravel-siem.svg?style=flat-square)](https://packagist.org/packages/cboxdk/laravel-siem)
[![Total Downloads](https://img.shields.io/packagist/dt/cboxdk/laravel-siem.svg?style=flat-square)](https://packagist.org/packages/cboxdk/laravel-siem)
![PHP Version](https://img.shields.io/packagist/php-v/cboxdk/laravel-siem?style=flat-square)

The SIEM log-streaming **delivery engine** for Laravel: a durable transactional
outbox, queued batched delivery with retry, dead-letter, and a per-stream circuit
breaker, SSRF-guarded HTTP egress, encrypted destination secrets, and per-field PII
redaction — shipping normalized security events to Splunk HEC, Elastic (ECS),
Graylog (GELF), ArcSight/syslog (CEF), any HTTP JSON collector, Datadog Logs, or
an Amazon S3 / S3-compatible / Google Cloud Storage bucket.

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

| Destination | Ships to | Framing | Credential (the encrypted `secret`) |
|-------------|----------|---------|-------------------------------------|
| `splunk_hec` | Splunk HEC | NDJSON to the collector event endpoint, `Authorization: Splunk <token>` | HEC token |
| `elastic_ecs` | Elastic / Kibana | ECS JSON documents (NDJSON) | bearer token or HMAC key |
| `graylog_gelf` | Graylog | GELF 1.1 over HTTP (never UDP) | bearer token or HMAC key |
| `cef_http` | ArcSight / syslog | CEF lines over HTTP | bearer token or HMAC key |
| `generic_json` | any HTTP collector | neutral single-line JSON | bearer token or HMAC key |
| `datadog` | Datadog Logs | Logs API v2 entries, gzip, `DD-API-KEY` | Datadog API key |
| `s3` | Amazon S3, MinIO, R2 | one NDJSON object per batch, gzip, SigV4 | secret access key — or none, with an assumed role |
| `gcs` | Google Cloud Storage | one NDJSON object per batch, gzip | service-account JSON key |

The first five POST to a collector URL you give. The three cloud destinations take
typed `options` instead (site, bucket, region, prefix, …) and derive their endpoint;
`Destination::httpCollectors()` lists the first five for a URL-and-token form. All
eight share the same outbox, batching, retry/backoff, dead-letter, circuit breaker,
redaction, SSRF guard and secret scrubbing.

Object storage destinations write
`{prefix}/{yyyy}/{mm}/{dd}/{hh}/{batch-id}.ndjson.gz` — partitioned by the UTC hour
the batch was written, one newline-delimited JSON event per line, a fresh ULID per
object (a retry never overwrites, so write-only permissions are enough). Set the
`gzip` option to `false` for plain `.ndjson`.

### Datadog

1. In Datadog, **Organization Settings → API Keys → New Key**. Use an *API key*
   (not an application key).
2. Pick the **site** your account lives on — the domain of the Datadog URL you sign
   in to: `datadoghq.com` (US1), `us3.datadoghq.com`, `us5.datadoghq.com`,
   `datadoghq.eu` (EU1), `ap1.datadoghq.com`, `ap2.datadoghq.com`, or
   `ddog-gov.com`. A key only works on its own site.
3. Register the stream:

```php
app(LogStreams::class)->create(
    name: 'datadog',
    destination: Destination::Datadog,
    endpointUrl: '',                     // derived: https://http-intake.logs.<site>/api/v2/logs
    secret: 'your-datadog-api-key',
    options: [
        'site' => 'datadoghq.eu',
        'service' => 'my-app',           // default: app.name
        'source' => 'cbox',              // ddsource, default: siem.datadog.source
        'tags' => ['env:prod', 'team:security'],
        // 'hostname' => 'id.example.com',  default: the host of app.url
    ],
);
```

Each event becomes one entry whose `message` is the event's JSON (Datadog parses it
into attributes). Requests respect the intake's limits — at most 1000 entries and
5 MB uncompressed per request — however `siem.batch` is tuned.

### Amazon S3 (and MinIO, Cloudflare R2)

1. Create the bucket (with your own retention/lifecycle rules).
2. Grant write-only access to the prefix — nothing to read, list or delete:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SiemWriteOnly",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::acme-audit-logs/cbox/audit/*"
    }
  ]
}
```

   With SSE-KMS on a customer-managed key, add
   `{"Effect": "Allow", "Action": "kms:GenerateDataKey", "Resource": "<key ARN>"}`.
3. Choose how the platform authenticates:
   - **Access key** — an IAM user with only that policy; give its access key ID as
     an option and its secret access key as the `secret`.
   - **Assumed role** (no customer secret stored) — attach the policy to a role
     whose trust policy lets the platform's AWS principal assume it **with the
     stream's external ID**, which is generated when you register the stream:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<platform-account-id>:user/<platform-user>" },
      "Action": "sts:AssumeRole",
      "Condition": { "StringEquals": { "sts:ExternalId": "<the stream's external_id>" } }
    }
  ]
}
```

     The platform's own identity is configured once in `siem.aws.*`
     (`SIEM_AWS_ACCESS_KEY_ID` / `SIEM_AWS_SECRET_ACCESS_KEY`) and needs only
     `sts:AssumeRole`.
4. Register the stream:

```php
$registered = app(LogStreams::class)->create(
    name: 's3-archive',
    destination: Destination::S3,
    endpointUrl: '',                     // AWS: derived from the region
    secret: 'secret-access-key',         // omit for an assumed role
    options: [
        'bucket' => 'acme-audit-logs',
        'region' => 'eu-west-1',
        'prefix' => 'cbox/audit',
        'access_key_id' => 'AKIA…',      // or: 'role_arn' => 'arn:aws:iam::123456789012:role/siem-writer'
        'sse' => 'aws:kms',              // optional: AES256 | aws:kms
        'kms_key_id' => 'alias/audit',   // optional, with aws:kms
    ],
);

$registered->stream->destinationOptions()['external_id'] ?? null; // show this for the trust policy
```

For **MinIO or R2**, pass the store's `https://` endpoint as `endpointUrl` (it goes
through the SSRF guard like any endpoint; R2's region is `auto`). Custom endpoints
use path-style addressing unless you set `path_style => false`.

Requests are signed with AWS Signature Version 4, implemented in-package on PHP's
`hash_hmac` and verified against AWS's published test vectors, so the AWS SDK is not
a dependency. To use the SDK's credential chain (instance profile, ECS task role, web
identity) on a single-tenant install, rebind `Contracts\AwsCredentialResolver`.

### Google Cloud Storage

1. Create the bucket, then a **service account** for the platform.
2. Grant it **`roles/storage.objectCreator` on the bucket only** — create objects,
   nothing else (no read, list, overwrite or delete):

```bash
gcloud storage buckets add-iam-policy-binding gs://acme-audit-logs \
  --member="serviceAccount:siem-writer@acme-audit.iam.gserviceaccount.com" \
  --role="roles/storage.objectCreator"
```

3. Create a **JSON key** for the service account and register the stream with it:

```php
app(LogStreams::class)->create(
    name: 'gcs-archive',
    destination: Destination::Gcs,
    endpointUrl: '',                     // https://storage.googleapis.com
    secret: file_get_contents('siem-writer-key.json'),
    options: ['bucket' => 'acme-audit-logs', 'prefix' => 'cbox/audit'],
);
```

The key signs a short-lived token request (RS256, via OpenSSL); the access token is
cached, encrypted, until just before it expires. The token endpoint is always
`siem.gcs.token_uri` — the key file's own `token_uri` is ignored, so a crafted key
cannot steer the platform's requests.

## Stream status and test delivery

- **Refusals are not retried blindly.** When a destination refuses the credentials
  or configuration (401/403, a missing bucket, a refused token exchange) the stream's
  circuit opens at once, its `last_error` / `last_failure_kind` record why, and its
  events stay pending **without spending their retry budget**. It probes once per
  cooldown; updating the stream's secret or options resets it immediately.
  Transient failures (timeouts, 429, 5xx) keep the bounded retry/backoff path.
- `$stream->health()` answers `healthy`, `degraded`, `paused` or
  `action_required` — the status to show next to a stream.
- `app(StreamTester::class)->test($stream)` sends one marked test event right now
  (outside the outbox) and returns a `TestDeliveryResult` (delivered, or the failure
  kind and a scrubbed error). A successful test also clears `action_required`.

## Testing

Compose `Cbox\LaravelSiem\Testing\InteractsWithLogStreams` into your `TestCase` to
run the whole pipeline in memory: `fakeStreamSink()` binds an in-memory
`FakeStreamSink`, `createLogStream(...)` registers through the real registry, and
`pumpStream($id)` runs a delivery cycle synchronously, and `testLogStream($id)` runs
a test delivery. `FakeStreamSink::refuseFor()` simulates refused credentials.
`FakeHttpTransport` programs the HTTP fake for testing the real sinks.

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
