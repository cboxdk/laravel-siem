<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Exceptions\UnsafeStreamUrl;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use SensitiveParameter;
use Throwable;

/**
 * The single egress path every sink (and every credential exchange) goes through,
 * so the guarantees are uniform and cannot be forgotten by a new destination:
 *
 * - **SSRF-guarded and DNS-pinned** — the exact request URL is validated and the
 *   connection pinned to the IPs just resolved (`cboxdk/laravel-ssrf`); redirects
 *   are refused. A blocked URL aborts before any byte leaves.
 * - **TLS verification ON** unless `siem.http.tls_verify = false`, which logs a
 *   loud warning on every request.
 * - **Bounded** connect/total timeouts.
 * - **Secret-scrubbed** — any transport error is scrubbed of every secret the
 *   caller names before it becomes a {@see StreamDeliveryFailed}.
 */
class Egress
{
    public function __construct(private readonly SecretScrubber $scrubber = new SecretScrubber) {}

    /**
     * @param  array<string, string>  $headers
     * @param  list<string|null>  $secrets  values to scrub from any error
     *
     * @throws StreamDeliveryFailed
     */
    public function send(
        string $method,
        string $url,
        array $headers,
        string $body,
        string $contentType,
        #[SensitiveParameter] array $secrets = [],
    ): Response {
        try {
            $pinned = SafeStreamUrl::pinnedOptions($url);
        } catch (UnsafeStreamUrl $e) {
            throw new StreamDeliveryFailed($this->scrubber->scrubAll($e->getMessage(), $secrets), previous: $e);
        }

        try {
            return Http::withHeaders($headers)
                ->withOptions([...$pinned, ...$this->tlsOptions()])
                ->withoutRedirecting()
                ->connectTimeout(max(1, Config::int('siem.http.connect_timeout', 5)))
                ->timeout(max(1, Config::int('siem.http.timeout', 15)))
                ->withBody($body, $contentType)
                ->send($method, $url);
        } catch (Throwable $e) {
            throw new StreamDeliveryFailed($this->scrubber->scrubAll($e->getMessage(), $secrets), previous: $e);
        }
    }

    /**
     * The standard mapping of an unsuccessful response: 401/403 mean the
     * destination refused the credentials (an operator must act); anything else
     * (408, 429, 5xx, …) is transient and retried with backoff.
     *
     * @param  list<string|null>  $secrets
     */
    public function failure(Response $response, string $what, #[SensitiveParameter] array $secrets = [], string $detail = ''): StreamDeliveryFailed
    {
        $status = $response->status();
        $message = $this->scrubber->scrubAll(trim("{$what} responded with HTTP {$status}. {$detail}"), $secrets);

        if ($status === 401 || $status === 403) {
            return DestinationRefused::authentication($message);
        }

        return new StreamDeliveryFailed($message);
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
}
