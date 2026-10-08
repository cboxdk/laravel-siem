<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support\Aws;

use Cbox\LaravelSiem\Contracts\AwsCredentialResolver;
use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Support\Config;
use Cbox\LaravelSiem\Support\Egress;
use Cbox\LaravelSiem\ValueObjects\AwsCredentials;
use Cbox\LaravelSiem\ValueObjects\Options\S3Options;
use DateTimeImmutable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Support\Carbon;
use SensitiveParameter;
use Throwable;

/**
 * The default {@see AwsCredentialResolver}.
 *
 * - **Access-key streams** sign with the stream's own access key ID (an option)
 *   and secret access key (the encrypted secret).
 * - **Assumed-role streams** call STS `AssumeRole` — signed with the platform's
 *   own identity from `siem.aws.access_key_id` / `secret_access_key` — for the
 *   stream's `role_arn` with its `external_id`, and cache the temporary
 *   credentials (encrypted, in the configured cache store) until five minutes
 *   before they expire. The customer's role trusts the platform's AWS principal
 *   and requires the external ID, so no customer secret is ever stored.
 *
 * Every STS call goes through {@see Egress}: SSRF-pinned, TLS on, scrubbed errors.
 */
class StsCredentialResolver implements AwsCredentialResolver
{
    private const string VERSION = '2011-06-15';

    public function __construct(
        private readonly SigV4Signer $signer,
        private readonly Egress $egress,
        private readonly CacheFactory $cache,
        private readonly StringEncrypter $encrypter,
    ) {}

    public function resolve(S3Options $options, #[SensitiveParameter] ?string $secret): AwsCredentials
    {
        if (! $options->usesAssumedRole()) {
            if ($options->accessKeyId === null || $secret === null || $secret === '') {
                throw DestinationRefused::configuration('The S3 stream has no access key configured.');
            }

            return new AwsCredentials($options->accessKeyId, $secret);
        }

        $key = $this->cacheKey($options);
        $cached = $this->fromCache($key);

        if ($cached !== null) {
            return $cached;
        }

        $credentials = $this->assumeRole($options);
        $ttl = $credentials->expiresAt === null
            ? 900
            : $credentials->expiresAt->getTimestamp() - Carbon::now()->getTimestamp() - 300;

        if ($ttl > 0) {
            $this->store()->put($key, $this->encrypter->encryptString((string) json_encode([
                'id' => $credentials->accessKeyId,
                'secret' => $credentials->secretAccessKey,
                'token' => $credentials->sessionToken,
                'expires' => $credentials->expiresAt?->getTimestamp(),
            ])), $ttl);
        }

        return $credentials;
    }

    public function forget(S3Options $options): void
    {
        if ($options->usesAssumedRole()) {
            $this->store()->forget($this->cacheKey($options));
        }
    }

    private function assumeRole(S3Options $options): AwsCredentials
    {
        $platformKey = Config::string('siem.aws.access_key_id');
        $platformSecret = Config::string('siem.aws.secret_access_key');

        if ($platformKey === null || $platformKey === '' || $platformSecret === null || $platformSecret === '') {
            throw DestinationRefused::configuration('Assumed-role S3 streams need the platform\'s own AWS identity (siem.aws.access_key_id / secret_access_key), and none is configured.');
        }

        $platform = new AwsCredentials($platformKey, $platformSecret, Config::string('siem.aws.session_token'));
        $endpoint = rtrim(Config::string('siem.aws.sts_endpoint') ?? 'https://sts.amazonaws.com', '/').'/';
        $region = Config::string('siem.aws.sts_region') ?? 'us-east-1';

        $body = http_build_query(array_filter([
            'Action' => 'AssumeRole',
            'DurationSeconds' => (string) max(900, min(43200, Config::int('siem.aws.role_duration', 3600))),
            'ExternalId' => $options->externalId,
            'RoleArn' => $options->roleArn,
            'RoleSessionName' => 'cbox-siem-'.substr(hash('sha256', $options->bucket), 0, 16),
            'Version' => self::VERSION,
        ], static fn (?string $value): bool => $value !== null), '', '&', PHP_QUERY_RFC3986);

        $contentType = 'application/x-www-form-urlencoded; charset=utf-8';
        $headers = $this->signer->sign(
            'POST', $endpoint, ['Content-Type' => $contentType], hash('sha256', $body),
            $platform, $region, 'sts', Carbon::now()->toDateTimeImmutable(),
        );
        unset($headers['Content-Type']);

        $secrets = [$platformSecret, $platform->sessionToken];
        $response = $this->egress->send('POST', $endpoint, $headers, $body, $contentType, $secrets);
        $xml = $response->body();

        if (! $response->successful()) {
            $code = AwsXml::value($xml, 'Code') ?? 'unknown';

            if ($response->status() === 403 || $code === 'AccessDenied') {
                throw DestinationRefused::authentication("AWS refused to let the platform assume the stream's role ({$code}). Check the role's trust policy names the platform's principal and requires this stream's external ID.");
            }

            if ($response->status() === 400 && $code === 'ValidationError') {
                throw DestinationRefused::configuration("AWS rejected the AssumeRole request ({$code}). Check the role ARN.");
            }

            throw $this->egress->failure($response, 'AWS STS', $secrets, "({$code})");
        }

        $id = AwsXml::value($xml, 'AccessKeyId');
        $secret = AwsXml::value($xml, 'SecretAccessKey');
        $token = AwsXml::value($xml, 'SessionToken');
        $expiration = AwsXml::value($xml, 'Expiration');

        if ($id === null || $secret === null || $token === null) {
            throw new StreamDeliveryFailed('AWS STS answered AssumeRole without credentials.');
        }

        try {
            $expires = $expiration === null ? null : new DateTimeImmutable($expiration);
        } catch (Throwable) {
            $expires = null;
        }

        return new AwsCredentials($id, $secret, $token, $expires);
    }

    private function fromCache(string $key): ?AwsCredentials
    {
        $payload = $this->store()->get($key);

        if (! is_string($payload)) {
            return null;
        }

        try {
            $data = json_decode($this->encrypter->decryptString($payload), true);
        } catch (Throwable) {
            return null;
        }

        if (! is_array($data) || ! is_string($data['id'] ?? null) || ! is_string($data['secret'] ?? null)) {
            return null;
        }

        $token = $data['token'] ?? null;
        $expires = $data['expires'] ?? null;

        return new AwsCredentials(
            $data['id'],
            $data['secret'],
            is_string($token) ? $token : null,
            is_int($expires) ? (new DateTimeImmutable)->setTimestamp($expires) : null,
        );
    }

    private function cacheKey(S3Options $options): string
    {
        return 'siem:aws-role:'.hash('sha256', ($options->roleArn ?? '').'|'.($options->externalId ?? '').'|'.(Config::string('siem.aws.access_key_id') ?? ''));
    }

    private function store(): Cache
    {
        return $this->cache->store(Config::string('siem.credentials_cache.store'));
    }
}
