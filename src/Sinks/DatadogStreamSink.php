<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Sinks;

use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\InvalidStreamConfiguration;
use Cbox\LaravelSiem\Support\Config;
use Cbox\LaravelSiem\Support\Egress;
use Cbox\LaravelSiem\ValueObjects\Options\DatadogOptions;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\ValueObjects\StreamTarget;

/**
 * Ships a batch to the Datadog Logs intake API v2 as a JSON array of log entries:
 *
 *     [{"ddsource": "cbox", "ddtags": "env:prod", "hostname": "id.example.com",
 *       "service": "my-app", "message": "<the serialized event>"}, …]
 *
 * gzip-compressed, with the API key in the `DD-API-KEY` header (never the URL),
 * to the intake host of the stream's site. Datadog parses the JSON `message` into
 * attributes on its side.
 *
 * The intake's limits are enforced here, not trusted to configuration: a batch is
 * split so no request carries more than 1000 entries or more than 5 MB of
 * uncompressed JSON. (The pump also cuts batches to those limits, so one batch is
 * normally one request.) 401/403 is a {@see DestinationRefused} — a wrong or
 * revoked key, or a key for another site; 408/429/5xx are transient.
 */
class DatadogStreamSink implements StreamSink
{
    public const int MAX_ENTRIES = 1000;

    public const int MAX_PAYLOAD_BYTES = 5_000_000;

    public function __construct(private readonly Egress $egress = new Egress) {}

    public function send(iterable $formattedRecords, StreamTarget $target): void
    {
        $apiKey = SinkOptions::string($target, 'secret');

        try {
            $options = DatadogOptions::fromArray($target->options);
        } catch (InvalidStreamConfiguration $e) {
            throw DestinationRefused::configuration($e->getMessage(), $e);
        }

        if ($apiKey === null || $apiKey === '') {
            throw DestinationRefused::configuration('The Datadog stream has no API key.');
        }

        $url = $this->intakeUrl($target->endpoint, $options);
        $base = $this->baseEntry($options);

        foreach ($this->chunks($formattedRecords, $base) as $json) {
            $payload = gzencode($json);
            $headers = ['DD-API-KEY' => $apiKey, 'Accept' => 'application/json'];

            if ($payload === false) {
                $payload = $json;
            } else {
                $headers['Content-Encoding'] = 'gzip';
            }

            $response = $this->egress->send('POST', $url, $headers, $payload, 'application/json', [$apiKey]);

            if (! $response->successful()) {
                throw $this->egress->failure($response, 'Datadog', [$apiKey]);
            }
        }
    }

    /**
     * The JSON request bodies for a batch: arrays of entries, each within the
     * intake's entry-count and uncompressed-size limits.
     *
     * @param  iterable<int, string>  $records
     * @param  array<string, string>  $base
     * @return list<string>
     */
    public function chunks(iterable $records, array $base): array
    {
        $chunks = [];
        $current = [];
        $bytes = 2; // the enclosing [ ]

        foreach ($records as $record) {
            $entry = json_encode([...$base, 'message' => $record], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

            if ($entry === false) {
                continue;
            }

            $size = strlen($entry) + 1; // plus its separating comma

            if ($current !== [] && (count($current) >= self::MAX_ENTRIES || $bytes + $size > self::MAX_PAYLOAD_BYTES)) {
                $chunks[] = '['.implode(',', $current).']';
                $current = [];
                $bytes = 2;
            }

            $current[] = $entry;
            $bytes += $size;
        }

        if ($current !== []) {
            $chunks[] = '['.implode(',', $current).']';
        }

        return $chunks;
    }

    /**
     * The attributes every entry of this stream carries.
     *
     * @return array<string, string>
     */
    public function baseEntry(DatadogOptions $options): array
    {
        $entry = [
            'ddsource' => $options->source ?? Config::string('siem.datadog.source') ?? 'cbox',
        ];

        if ($options->tags !== null) {
            $entry['ddtags'] = $options->tags;
        }

        $entry['hostname'] = $options->hostname ?? $this->defaultHostname();
        $entry['service'] = $options->service ?? $this->defaultService();

        return $entry;
    }

    private function intakeUrl(string $endpoint, DatadogOptions $options): string
    {
        if ($endpoint === '') {
            return $options->defaultEndpoint();
        }

        $path = parse_url($endpoint, PHP_URL_PATH);

        // A bare custom host (a proxy) gets the intake path appended.
        if ($path === null || $path === false || $path === '' || $path === '/') {
            return rtrim($endpoint, '/').'/api/v2/logs';
        }

        return $endpoint;
    }

    private function defaultService(): string
    {
        $name = Config::string('siem.datadog.service') ?? Config::string('app.name');

        return $name !== null && $name !== '' ? $name : 'cbox-siem';
    }

    private function defaultHostname(): string
    {
        $host = parse_url(Config::string('app.url') ?? '', PHP_URL_HOST);

        if (is_string($host) && $host !== '' && $host !== 'localhost') {
            return $host;
        }

        $local = gethostname();

        return $local === false || $local === '' ? 'cbox-siem' : $local;
    }
}
