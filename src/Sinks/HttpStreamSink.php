<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Sinks;

use Cbox\LaravelSiem\Enums\AuthScheme;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Exceptions\UnsafeStreamUrl;
use Cbox\LaravelSiem\Support\Config;
use Cbox\LaravelSiem\Support\SafeStreamUrl;
use Cbox\LaravelSiem\Support\SecretScrubber;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\ValueObjects\StreamTarget;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

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
 */
class HttpStreamSink implements StreamSink
{
    public function __construct(private readonly SecretScrubber $scrubber = new SecretScrubber) {}

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

        // SSRF: resolve once, pin to the validated IPs, and refuse redirects. A
        // blocked endpoint throws — the send aborts before any bytes leave.
        try {
            $pinned = SafeStreamUrl::pinnedOptions($url);
        } catch (UnsafeStreamUrl $e) {
            throw new StreamDeliveryFailed($this->scrubber->scrub($e->getMessage(), $secret), previous: $e);
        }

        $headers = $this->authHeaders($auth, $secret, $body);
        $contentType = $this->option($target, 'content_type') ?? 'application/json';

        if ($this->option($target, 'gzip') === '1') {
            $encoded = gzencode($body);
            if ($encoded !== false) {
                $body = $encoded;
                $headers['Content-Encoding'] = 'gzip';
            }
        }

        try {
            $response = Http::withHeaders($headers)
                ->withOptions([...$pinned, ...$this->tlsOptions()])
                ->withoutRedirecting()
                ->connectTimeout($this->connectTimeout())
                ->timeout($this->timeout())
                ->withBody($body, $contentType)
                ->post($url);
        } catch (Throwable $e) {
            throw new StreamDeliveryFailed($this->scrubber->scrub($e->getMessage(), $secret), previous: $e);
        }

        if (! $response->successful()) {
            throw new StreamDeliveryFailed(
                $this->scrubber->scrub("destination responded with HTTP {$response->status()}", $secret),
            );
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
        if (config('siem.http.tls_verify', true) !== false) {
            return [];
        }

        Log::warning('siem: TLS certificate verification is DISABLED for stream delivery (siem.http.tls_verify=false). Never do this in production.');

        return ['verify' => false];
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

    private function connectTimeout(): int
    {
        return max(1, Config::int('siem.http.connect_timeout', 5));
    }

    private function timeout(): int
    {
        return max(1, Config::int('siem.http.timeout', 15));
    }
}
