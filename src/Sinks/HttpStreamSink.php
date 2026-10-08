<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Sinks;

use Cbox\LaravelSiem\Enums\AuthScheme;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Support\Egress;
use Cbox\LaravelSiem\Support\SecretScrubber;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\ValueObjects\StreamTarget;

/**
 * The real {@see StreamSink}: ships a batch of already-formatted records to a SIEM
 * over HTTP, with every egress footgun closed.
 *
 * - **SSRF-guarded** — the endpoint is validated and pinned to its resolved IPs
 *   via `cboxdk/laravel-ssrf`, and redirects are refused (a 30x to an internal
 *   host is another SSRF path). A blocked endpoint aborts the send; nothing goes
 *   out.
 * - **TLS verification ON** — certificate verification is never disabled silently.
 *   The only way to turn it off is `siem.http.tls_verify = false`, which logs a
 *   loud warning on every send.
 * - **Per-destination framing & auth** — Splunk HEC gets an NDJSON body to the
 *   collector event endpoint with `Authorization: Splunk <token>`; ECS/GELF/CEF/
 *   JSON get an NDJSON (or newline-joined) body with a bearer or HMAC-signed
 *   credential.
 * - **Secret hygiene** — the token is only ever a header/signature input, never
 *   logged, and any failure message is scrubbed of it before it leaves this class.
 * - **Refusals are not retried blindly** — a 401/403 is a
 *   {@see DestinationRefused}: the pump opens the
 *   circuit immediately and flags the stream instead of burning retries.
 *
 * The request itself goes through the shared {@see Egress} path.
 */
class HttpStreamSink implements StreamSink
{
    private readonly Egress $egress;

    public function __construct(SecretScrubber $scrubber = new SecretScrubber, ?Egress $egress = null)
    {
        $this->egress = $egress ?? new Egress($scrubber);
    }

    public function send(iterable $formattedRecords, StreamTarget $target): void
    {
        $records = [];
        foreach ($formattedRecords as $record) {
            $records[] = $record;
        }

        if ($records === []) {
            return;
        }

        $destination = $this->destination($target);
        $secret = $this->option($target, 'secret');
        $auth = $this->auth($target, $destination);
        $url = $this->resolveUrl($destination, $target->endpoint);
        $body = implode("\n", $records);

        $headers = $this->authHeaders($auth, $secret, $body);
        $contentType = $this->option($target, 'content_type') ?? 'application/json';

        if ($this->option($target, 'gzip') === '1') {
            $encoded = gzencode($body);
            if ($encoded !== false) {
                $body = $encoded;
                $headers['Content-Encoding'] = 'gzip';
            }
        }

        // SSRF (resolve once, pin, refuse redirects), TLS, timeouts and error
        // scrubbing all live in the shared egress path. A blocked endpoint throws
        // before any bytes leave.
        $response = $this->egress->send('POST', $url, $headers, $body, $contentType, [$secret]);

        if (! $response->successful()) {
            // 401/403 become a DestinationRefused (the circuit opens at once, an
            // operator must fix the token); anything else is retried.
            throw $this->egress->failure($response, 'destination', [$secret]);
        }
    }

    /**
     * The Guzzle options that control TLS. Empty by default, so certificate
     * verification stays ON (Guzzle verifies unless told otherwise). `verify` is
     * set false ONLY when explicitly disabled in config — and never quietly.
     *
     * @return array<string, mixed>
     */
    public function tlsOptions(): array
    {
        return $this->egress->tlsOptions();
    }

    private function resolveUrl(Destination $destination, string $endpoint): string
    {
        if ($destination !== Destination::SplunkHec) {
            return $endpoint;
        }

        // Splunk HEC events with `fields`/structured bodies go to the collector
        // EVENT endpoint. Append it only when the operator gave a bare host.
        $path = parse_url($endpoint, PHP_URL_PATH);

        if ($path === null || $path === false || $path === '' || $path === '/') {
            return rtrim($endpoint, '/').'/services/collector/event';
        }

        return $endpoint;
    }

    /**
     * @return array<string, string>
     */
    private function authHeaders(AuthScheme $auth, ?string $secret, string $body): array
    {
        if ($secret === null || $secret === '') {
            return [];
        }

        return match ($auth) {
            AuthScheme::None => [],
            AuthScheme::Splunk => ['Authorization' => 'Splunk '.$secret],
            AuthScheme::Bearer => ['Authorization' => 'Bearer '.$secret],
            AuthScheme::Hmac => $this->hmacHeaders($secret, $body),
        };
    }

    /**
     * @return array<string, string>
     */
    private function hmacHeaders(string $secret, string $body): array
    {
        // Sign `timestamp.body` (Stripe-style) over the uncompressed payload so a
        // receiver can bind the signature to a moment and reject a replay.
        $timestamp = time();
        $signature = hash_hmac('sha256', $timestamp.'.'.$body, $secret);

        return [
            'X-Cbox-Timestamp' => (string) $timestamp,
            'X-Cbox-Signature' => 't='.$timestamp.',v1='.$signature,
        ];
    }

    private function destination(StreamTarget $target): Destination
    {
        return Destination::tryFrom($this->option($target, 'destination') ?? '') ?? Destination::GenericJson;
    }

    private function auth(StreamTarget $target, Destination $destination): AuthScheme
    {
        return AuthScheme::tryFrom($this->option($target, 'auth') ?? '') ?? $destination->defaultAuth();
    }

    private function option(StreamTarget $target, string $key): ?string
    {
        $value = $target->options[$key] ?? null;

        if ($value === null) {
            return null;
        }

        if (is_bool($value)) {
            return $value ? '1' : '0';
        }

        return (string) $value;
    }
}
