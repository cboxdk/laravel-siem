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
 */
enum Destination: string
{
    case SplunkHec = 'splunk_hec';
    case ElasticEcs = 'elastic_ecs';
    case GraylogGelf = 'graylog_gelf';
    case CefHttp = 'cef_http';
    case GenericJson = 'generic_json';

    /**
     * The authentication scheme this destination defaults to when a stream does
     * not override it. Splunk HEC always uses its own token header; the others
     * default to a bearer token when a secret is present.
     */
    public function defaultAuth(): AuthScheme
    {
        return match ($this) {
            self::SplunkHec => AuthScheme::Splunk,
            default => AuthScheme::Bearer,
        };
    }
}
