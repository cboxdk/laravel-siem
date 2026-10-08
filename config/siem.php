<?php

declare(strict_types=1);
use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\Models\StreamDelivery;

return [

    /*
    |--------------------------------------------------------------------------
    | Queue Connection & Queue
    |--------------------------------------------------------------------------
    |
    | The pump that drains the transactional outbox and ships batches to each
    | destination runs on a queue, never on the request thread. Point these at a
    | durable connection (redis/database/sqs); the default (null) uses the
    | application's default connection.
    |
    */

    'queue' => [
        'connection' => env('SIEM_QUEUE_CONNECTION'),
        'queue' => env('SIEM_QUEUE', 'default'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Scheduled Pump
    |--------------------------------------------------------------------------
    |
    | When enabled the service provider registers a scheduled task that, every
    | minute, dispatches a per-stream pump job for every enabled stream. Turn it
    | off to drive delivery yourself (dispatch PumpStreamDeliveries by hand).
    |
    */

    'schedule' => [
        'enabled' => env('SIEM_SCHEDULE', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Batching Bounds (triple-bounded)
    |--------------------------------------------------------------------------
    |
    | A pump run drains pending deliveries into delivery batches. Every batch is
    | bounded three ways at once, and whichever bound is hit first cuts the
    | batch — so a single request can never blow past a destination's payload
    | limit or hold events for longer than the latency budget:
    |
    |   max_records — most events in one HTTP request.
    |   max_bytes   — most formatted bytes in one request body.
    |   max_age     — seconds; a batch is cut once it spans more than this,
    |                 bounding end-to-end delivery latency.
    |
    */

    'batch' => [
        'max_records' => (int) env('SIEM_BATCH_MAX_RECORDS', 500),
        'max_bytes' => (int) env('SIEM_BATCH_MAX_BYTES', 512 * 1024),
        'max_age' => (int) env('SIEM_BATCH_MAX_AGE', 5),
        'fetch_limit' => (int) env('SIEM_BATCH_FETCH_LIMIT', 5000),
    ],

    /*
    |--------------------------------------------------------------------------
    | Retry & Dead-Letter
    |--------------------------------------------------------------------------
    |
    | A failed delivery is retried with bounded exponential backoff plus jitter.
    | Once `max_attempts` is reached it is marked `dead` (dead-lettered), retained
    | for inspection, and NEVER retried again — retries are bounded, never a loop.
    |
    */

    'retry' => [
        'max_attempts' => (int) env('SIEM_MAX_ATTEMPTS', 12),
        'base_seconds' => (int) env('SIEM_RETRY_BASE_SECONDS', 5),
        'max_seconds' => (int) env('SIEM_RETRY_MAX_SECONDS', 3600),
    ],

    /*
    |--------------------------------------------------------------------------
    | Per-Stream Circuit Breaker
    |--------------------------------------------------------------------------
    |
    | After `failure_threshold` consecutive failures a stream's breaker OPENS:
    | delivery pauses for `cooldown_seconds`, the health state is surfaced on the
    | stream, and other streams are unaffected. After the cooldown one probe is
    | allowed; a success closes the breaker, a failure re-opens it. A failing
    | destination never stops the app, the caller, or another stream — but its
    | failures are always counted, never black-holed.
    |
    */

    'circuit_breaker' => [
        'failure_threshold' => (int) env('SIEM_BREAKER_THRESHOLD', 5),
        'cooldown_seconds' => (int) env('SIEM_BREAKER_COOLDOWN', 300),
    ],

    /*
    |--------------------------------------------------------------------------
    | Backpressure (bounded outbox)
    |--------------------------------------------------------------------------
    |
    | The outbox is bounded per stream. When the number of pending deliveries for
    | a stream reaches `max_pending`, the `policy` decides what gives:
    |
    |   "drop_oldest" — dead-letter the oldest pending rows to make room for new
    |                   events (default; keeps the freshest security signal).
    |   "reject_new"  — dead-letter the incoming event instead.
    |
    | Either way the shed rows are dead-lettered (never silently dropped), a
    | warning is logged, and an OutboxOverflowed event fires for a metric hook.
    |
    */

    'backpressure' => [
        'max_pending' => (int) env('SIEM_MAX_PENDING', 100000),
        'policy' => env('SIEM_BACKPRESSURE_POLICY', 'drop_oldest'),
    ],

    /*
    |--------------------------------------------------------------------------
    | HTTP Egress
    |--------------------------------------------------------------------------
    |
    | Every outbound request is SSRF-guarded (cboxdk/laravel-ssrf): the endpoint
    | is resolved once, pinned to the validated IPs, and redirects are refused.
    |
    | tls_verify — TLS certificate verification. ON by default and there is no
    |              silent way to disable it: setting this false logs a loud
    |              warning on every send. Never disable it in production.
    |
    */

    'http' => [
        'verify_url' => env('SIEM_VERIFY_URL', true),
        'tls_verify' => env('SIEM_TLS_VERIFY', true),
        'connect_timeout' => (int) env('SIEM_CONNECT_TIMEOUT', 5),
        'timeout' => (int) env('SIEM_TIMEOUT', 15),
        'gzip' => env('SIEM_GZIP', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Datadog
    |--------------------------------------------------------------------------
    |
    | Defaults for the attributes every Datadog log entry carries, used when a
    | stream does not set its own: `ddsource` and `service` (the latter falls
    | back to app.name). The hostname defaults to the host of app.url.
    |
    */

    'datadog' => [
        'source' => env('SIEM_DATADOG_SOURCE', 'cbox'),
        'service' => env('SIEM_DATADOG_SERVICE'),
    ],

    /*
    |--------------------------------------------------------------------------
    | AWS (assumed-role S3 streams)
    |--------------------------------------------------------------------------
    |
    | The platform's OWN AWS identity, used only to call STS AssumeRole for
    | streams configured with a role ARN (the customer's role trusts this
    | principal and requires the stream's external ID). Access-key streams do not
    | use it. Leave unset to offer access-key streams only.
    |
    */

    'aws' => [
        'access_key_id' => env('SIEM_AWS_ACCESS_KEY_ID'),
        'secret_access_key' => env('SIEM_AWS_SECRET_ACCESS_KEY'),
        'session_token' => env('SIEM_AWS_SESSION_TOKEN'),
        'sts_endpoint' => env('SIEM_AWS_STS_ENDPOINT', 'https://sts.amazonaws.com'),
        'sts_region' => env('SIEM_AWS_STS_REGION', 'us-east-1'),
        'role_duration' => (int) env('SIEM_AWS_ROLE_DURATION', 3600),
    ],

    /*
    |--------------------------------------------------------------------------
    | Google Cloud Storage
    |--------------------------------------------------------------------------
    |
    | The OAuth token endpoint service-account keys are exchanged at. A key
    | file's own token_uri is ignored on purpose (it would let a crafted key
    | choose where the platform sends requests).
    |
    */

    'gcs' => [
        'token_uri' => env('SIEM_GCS_TOKEN_URI', 'https://oauth2.googleapis.com/token'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Credentials Cache
    |--------------------------------------------------------------------------
    |
    | Where short-lived cloud credentials (GCS access tokens, assumed-role STS
    | credentials) are cached, encrypted with the app key, until shortly before
    | they expire. null uses the default cache store.
    |
    */

    'credentials_cache' => [
        'store' => env('SIEM_CREDENTIALS_CACHE_STORE'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Models
    |--------------------------------------------------------------------------
    |
    | Resolve the Eloquent models through the container so a host can subclass
    | them (add tenancy scopes, casts, relations) while the package still owns the
    | schema.
    |
    */

    'models' => [
        'log_stream' => LogStream::class,
        'stream_delivery' => StreamDelivery::class,
    ],

];
