<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support\Aws;

use Cbox\LaravelSiem\Contracts\AwsCredentialResolver;
use Cbox\LaravelSiem\ValueObjects\AwsCredentials;
use DateTimeImmutable;
use DateTimeZone;
use SensitiveParameter;

/**
 * AWS Signature Version 4 (header-based) for the two calls this package makes: an
 * S3 `PutObject` and an STS `AssumeRole`. It is the documented algorithm and
 * nothing more — canonical request, string-to-sign, the HMAC-SHA256 key-derivation
 * chain — built on PHP's own `hash`/`hash_hmac`, and proven against AWS's
 * published Signature V4 test vectors (see `tests/Unit/SigV4SignerTest.php`).
 *
 * Why not the AWS SDK: it is a ~30 MB dependency for two signed requests, and this
 * package's rule is no heavy third-party runtime dependency without a confirmed
 * need. A host that wants the SDK's credential chain (instance profiles, web
 * identity, SSO) rebinds {@see AwsCredentialResolver}
 * instead; the signer stays the same.
 *
 * Path encoding follows S3's rule (each segment URI-encoded once). STS signs `/`,
 * where the services' rules coincide.
 */
class SigV4Signer
{
    public const string ALGORITHM = 'AWS4-HMAC-SHA256';

    /**
     * Sign a request. Returns the headers to send: the input headers plus
     * `X-Amz-Date`, `X-Amz-Security-Token` (for temporary credentials) and
     * `Authorization`. Every input header is signed, so pass exactly the headers
     * that go on the wire (`Host` is derived from the URL and always signed).
     *
     * @param  array<string, string>  $headers
     * @return array<string, string>
     */
    public function sign(
        string $method,
        string $url,
        array $headers,
        string $payloadHash,
        AwsCredentials $credentials,
        string $region,
        string $service,
        DateTimeImmutable $now,
    ): array {
        $amzDate = $now->setTimezone(new DateTimeZone('UTC'))->format('Ymd\THis\Z');
        $date = substr($amzDate, 0, 8);

        $headers['X-Amz-Date'] = $amzDate;

        if ($credentials->sessionToken !== null && $credentials->sessionToken !== '') {
            $headers['X-Amz-Security-Token'] = $credentials->sessionToken;
        }

        [$canonical, $signedHeaders] = $this->canonicalRequest($method, $url, $headers, $payloadHash);
        $scope = "{$date}/{$region}/{$service}/aws4_request";
        $stringToSign = self::ALGORITHM."\n{$amzDate}\n{$scope}\n".hash('sha256', $canonical);
        $signature = hash_hmac('sha256', $stringToSign, $this->signingKey($credentials->secretAccessKey, $date, $region, $service));

        $headers['Authorization'] = self::ALGORITHM
            ." Credential={$credentials->accessKeyId}/{$scope}, SignedHeaders={$signedHeaders}, Signature={$signature}";

        return $headers;
    }

    /**
     * The canonical request and the signed-headers list for it.
     *
     * @param  array<string, string>  $headers
     * @return array{string, string}
     */
    public function canonicalRequest(string $method, string $url, array $headers, string $payloadHash): array
    {
        $parts = parse_url($url);
        $parts = is_array($parts) ? $parts : [];

        $canonicalHeaders = ['host' => $this->hostHeader($parts)];

        foreach ($headers as $name => $value) {
            $canonicalHeaders[strtolower($name)] = preg_replace('/\s+/', ' ', trim($value)) ?? trim($value);
        }

        ksort($canonicalHeaders, SORT_STRING);

        $headerBlock = '';
        foreach ($canonicalHeaders as $name => $value) {
            $headerBlock .= $name.':'.$value."\n";
        }

        $signedHeaders = implode(';', array_keys($canonicalHeaders));

        $canonical = implode("\n", [
            strtoupper($method),
            $this->canonicalUri($parts['path'] ?? ''),
            $this->canonicalQuery($parts['query'] ?? ''),
            $headerBlock,
            $signedHeaders,
            $payloadHash,
        ]);

        return [$canonical, $signedHeaders];
    }

    /**
     * The derived signing key: HMAC chain over date, region, service and the
     * `aws4_request` terminator, seeded with `"AWS4" . secret`.
     */
    public function signingKey(#[SensitiveParameter] string $secretAccessKey, string $date, string $region, string $service): string
    {
        $kDate = hash_hmac('sha256', $date, 'AWS4'.$secretAccessKey, true);
        $kRegion = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $service, $kRegion, true);

        return hash_hmac('sha256', 'aws4_request', $kService, true);
    }

    /**
     * @param  array<string, int|string>  $parts
     */
    private function hostHeader(array $parts): string
    {
        $host = strtolower((string) ($parts['host'] ?? ''));
        $port = isset($parts['port']) ? (int) $parts['port'] : null;
        $scheme = strtolower((string) ($parts['scheme'] ?? 'https'));
        $default = $scheme === 'http' ? 80 : 443;

        return $port === null || $port === $default ? $host : $host.':'.$port;
    }

    private function canonicalUri(string $path): string
    {
        if ($path === '') {
            return '/';
        }

        return implode('/', array_map(
            static fn (string $segment): string => rawurlencode(rawurldecode($segment)),
            explode('/', $path),
        ));
    }

    private function canonicalQuery(string $query): string
    {
        if ($query === '') {
            return '';
        }

        $pairs = [];

        foreach (explode('&', $query) as $pair) {
            if ($pair === '') {
                continue;
            }

            [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $pairs[] = [rawurlencode(rawurldecode($key)), rawurlencode(rawurldecode($value))];
        }

        usort($pairs, static fn (array $a, array $b): int => [$a[0], $a[1]] <=> [$b[0], $b[1]]);

        return implode('&', array_map(static fn (array $pair): string => $pair[0].'='.$pair[1], $pairs));
    }
}
