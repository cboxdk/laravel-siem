<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Enums;

/**
 * The kind of SIEM a stream ships to. The value selects the core formatter and
 * the sink's per-destination framing and authentication:
 *
 * - `splunk_hec`    — Splunk HTTP Event Collector; NDJSON body, `Authorization:
 *                     Splunk <token>`, delivered to the collector event endpoint.
 * - `elastic_ecs`   — Elastic Common Schema JSON; NDJSON body over HTTP.
 * - `graylog_gelf`  — Graylog GELF 1.1 over HTTP (never UDP for audit data).
 * - `cef_http`      — ArcSight/syslog CEF lines over HTTP.
 * - `generic_json`  — the neutral single-line JSON formatter for any HTTP sink.
 * - `datadog`       — the Datadog Logs intake API v2; JSON log entries (gzip),
 *                     `DD-API-KEY` header, site-selectable intake host.
 * - `s3`            — Amazon S3 (or an S3-compatible store: MinIO, R2); each batch
 *                     is one time-partitioned NDJSON object, SigV4-signed.
 * - `gcs`           — Google Cloud Storage; each batch is one time-partitioned
 *                     NDJSON object, authorized by a service-account key.
 *
 * The last three are "cloud" destinations: they carry typed, destination-specific
 * settings in the stream's `options` (see {@see self::requiresOptions()}) and
 * authenticate their own way, so the {@see AuthScheme} does not apply to them.
 */
enum Destination: string
{
    case SplunkHec = 'splunk_hec';
    case ElasticEcs = 'elastic_ecs';
    case GraylogGelf = 'graylog_gelf';
    case CefHttp = 'cef_http';
    case GenericJson = 'generic_json';
    case Datadog = 'datadog';
    case S3 = 's3';
    case Gcs = 'gcs';

    /**
     * The destinations that POST to an operator-supplied HTTP collector URL with
     * an {@see AuthScheme} — the original five. A host whose UI only collects an
     * endpoint URL and a token offers exactly these.
     *
     * @return list<self>
     */
    public static function httpCollectors(): array
    {
        return array_values(array_filter(self::cases(), static fn (self $destination): bool => ! $destination->requiresOptions()));
    }

    /**
     * The authentication scheme this destination defaults to when a stream does
     * not override it. Splunk HEC always uses its own token header; the HTTP
     * collectors default to a bearer token when a secret is present; the cloud
     * destinations authenticate with their own mechanism (an API key header, AWS
     * SigV4, a Google OAuth token), so no generic scheme applies.
     */
    public function defaultAuth(): AuthScheme
    {
        return match ($this) {
            self::SplunkHec => AuthScheme::Splunk,
            self::Datadog, self::S3, self::Gcs => AuthScheme::None,
            default => AuthScheme::Bearer,
        };
    }

    /**
     * True for the destinations configured with typed `options` (site, bucket,
     * region, …) rather than a bare collector URL.
     */
    public function requiresOptions(): bool
    {
        return match ($this) {
            self::Datadog, self::S3, self::Gcs => true,
            default => false,
        };
    }

    /**
     * True for the object stores, which write one NDJSON object per batch.
     */
    public function isObjectStorage(): bool
    {
        return $this === self::S3 || $this === self::Gcs;
    }

    /**
     * The destination's hard per-request record cap, or null when it has none.
     * The pump never cuts a batch larger than this, whatever `siem.batch` says.
     */
    public function maxBatchRecords(): ?int
    {
        return match ($this) {
            // Datadog Logs API v2: at most 1000 entries per request.
            self::Datadog => 1000,
            default => null,
        };
    }

    /**
     * The destination's hard per-request payload cap in (uncompressed) bytes, or
     * null when it has none.
     */
    public function maxBatchBytes(): ?int
    {
        return match ($this) {
            // Datadog Logs API v2: at most 5 MB uncompressed per request. Kept a
            // little under, because the batcher sizes raw events, not entries.
            self::Datadog => 4_500_000,
            default => null,
        };
    }
}
