<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Sinks;

use Cbox\LaravelSiem\Contracts\AwsCredentialResolver;
use Cbox\LaravelSiem\Enums\S3Encryption;
use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\InvalidStreamConfiguration;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Support\Aws\AwsXml;
use Cbox\LaravelSiem\Support\Aws\SigV4Signer;
use Cbox\LaravelSiem\Support\Egress;
use Cbox\LaravelSiem\Support\ObjectKey;
use Cbox\LaravelSiem\ValueObjects\Options\S3Options;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\ValueObjects\StreamTarget;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Carbon;

/**
 * Writes each batch to Amazon S3 (or an S3-compatible store — MinIO, Cloudflare
 * R2) as ONE newline-delimited JSON object, gzip-compressed by default, under
 * `{prefix}/{yyyy}/{mm}/{dd}/{hh}/{batch-id}.ndjson.gz` (see {@see ObjectKey}).
 *
 * The `PutObject` is SigV4-signed ({@see SigV4Signer}) with credentials from the
 * {@see AwsCredentialResolver} (a static key, or an assumed role), carries the
 * payload's SHA-256 so S3 verifies integrity, and optionally requests server-side
 * encryption. The request goes through {@see Egress}: the exact object URL is
 * SSRF-checked and DNS-pinned, TLS is verified, redirects are refused.
 *
 * Failure mapping: refused credentials (401/403) and a missing or misplaced
 * bucket (404 `NoSuchBucket`, 301 `PermanentRedirect`, `AuthorizationHeaderMalformed`)
 * are {@see DestinationRefused} — no amount of retrying fixes them; an expired
 * temporary credential is dropped from the cache and retried; everything else is
 * transient.
 */
class S3StreamSink implements StreamSink
{
    private const array CONFIGURATION_CODES = [
        'NoSuchBucket', 'PermanentRedirect', 'AuthorizationHeaderMalformed',
        'InvalidBucketName', 'IllegalLocationConstraintException',
    ];

    private const array EXPIRED_CODES = ['ExpiredToken', 'TokenRefreshRequired'];

    public function __construct(
        private readonly SigV4Signer $signer,
        private readonly AwsCredentialResolver $credentials,
        private readonly Egress $egress = new Egress,
    ) {}

    public function send(iterable $formattedRecords, StreamTarget $target): void
    {
        $records = [];
        foreach ($formattedRecords as $record) {
            $records[] = $record;
        }

        if ($records === []) {
            return;
        }

        $secret = SinkOptions::string($target, 'secret');

        try {
            $options = S3Options::fromArray($target->options);
        } catch (InvalidStreamConfiguration $e) {
            throw DestinationRefused::configuration($e->getMessage(), $e);
        }

        $now = Carbon::now()->toDateTimeImmutable();
        $body = implode("\n", $records)."\n";
        $payload = $options->gzip ? (gzencode($body) ?: $body) : $body;
        $gzip = $options->gzip && $payload !== $body;
        $url = $this->objectUrl($target->endpoint, $options, ObjectKey::make($options->prefix, $now, $gzip));

        $credentials = $this->credentials->resolve($options, $secret);
        $payloadHash = hash('sha256', $payload);

        $headers = ['x-amz-content-sha256' => $payloadHash];

        if ($options->encryption !== null) {
            $headers['x-amz-server-side-encryption'] = $options->encryption->value;
        }

        if ($options->encryption === S3Encryption::Kms && $options->kmsKeyId !== null) {
            $headers['x-amz-server-side-encryption-aws-kms-key-id'] = $options->kmsKeyId;
        }

        $signed = $this->signer->sign('PUT', $url, $headers, $payloadHash, $credentials, $options->region, 's3', $now);
        $secrets = [$secret, $credentials->secretAccessKey, $credentials->sessionToken];

        $response = $this->egress->send('PUT', $url, $signed, $payload, $gzip ? 'application/gzip' : 'application/x-ndjson', $secrets);

        if (! $response->successful()) {
            throw $this->failure($response, $options, $secrets);
        }
    }

    /**
     * The object URL: virtual-hosted (`https://bucket.s3.region.amazonaws.com/key`)
     * on AWS, path-style (`https://endpoint/bucket/key`) on a custom endpoint or
     * for a dotted bucket name (whose virtual host would not match the TLS
     * certificate) — unless the stream's `path_style` option says otherwise.
     */
    public function objectUrl(string $endpoint, S3Options $options, string $key): string
    {
        $endpoint = rtrim($endpoint === '' ? $options->defaultEndpoint() : $endpoint, '/');
        $parts = parse_url($endpoint);
        $host = is_array($parts) ? strtolower($parts['host'] ?? '') : '';
        $isAws = str_ends_with($host, '.amazonaws.com') || str_ends_with($host, '.amazonaws.com.cn');
        $pathStyle = $options->pathStyle ?? (! $isAws || str_contains($options->bucket, '.'));
        $encodedKey = ObjectKey::encode($key);

        if ($pathStyle || ! is_array($parts)) {
            return $endpoint.'/'.$options->bucket.'/'.$encodedKey;
        }

        $port = isset($parts['port']) ? ':'.$parts['port'] : '';
        $path = rtrim($parts['path'] ?? '', '/');

        return ($parts['scheme'] ?? 'https').'://'.$options->bucket.'.'.$host.$port.$path.'/'.$encodedKey;
    }

    /**
     * @param  list<string|null>  $secrets
     */
    private function failure(Response $response, S3Options $options, array $secrets): StreamDeliveryFailed
    {
        $status = $response->status();
        $code = AwsXml::value($response->body(), 'Code') ?? 'unknown';
        $code = preg_match('/^[A-Za-z0-9.]{1,64}$/', $code) === 1 ? $code : 'unknown';

        if (in_array($code, self::EXPIRED_CODES, true)) {
            $this->credentials->forget($options);

            return new StreamDeliveryFailed("S3 rejected expired temporary credentials ({$code}); they will be refreshed.");
        }

        if (in_array($code, self::CONFIGURATION_CODES, true) || $status === 404 || $status === 301) {
            return DestinationRefused::configuration("S3 cannot find bucket [{$options->bucket}] where the stream points ({$code}, HTTP {$status}). Check the bucket name, region and endpoint.");
        }

        if ($status === 401 || $status === 403) {
            $this->credentials->forget($options);

            return DestinationRefused::authentication("S3 refused the stream's credentials for bucket [{$options->bucket}] ({$code}, HTTP {$status}). Check the key or role has s3:PutObject on the prefix.");
        }

        return $this->egress->failure($response, 'S3', $secrets, "({$code})");
    }
}
