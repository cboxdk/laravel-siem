<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support\Gcp;

use Cbox\LaravelSiem\Contracts\GcsAccessTokens;
use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Support\Config;
use Cbox\LaravelSiem\Support\Egress;
use Cbox\LaravelSiem\ValueObjects\GcpServiceAccount;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Support\Carbon;
use Throwable;

/**
 * The default {@see GcsAccessTokens}: the OAuth 2.0 JWT-bearer grant (RFC 7523)
 * Google documents for service accounts.
 *
 * A short JWT (`iss` = the account, `scope` = devstorage read/write, `aud` = the
 * token endpoint, one hour) is signed RS256 with the key file's private key —
 * PHP's OpenSSL `openssl_sign`, no hand-rolled cryptography, and nothing here ever
 * VERIFIES a token — then exchanged at the token endpoint. The access token is
 * cached, encrypted, until a minute before it expires.
 *
 * The token endpoint is `siem.gcs.token_uri` (Google's by default), never the key
 * file's own `token_uri`: a crafted key file must not be able to choose where the
 * platform sends a signed assertion. The exchange goes through {@see Egress}.
 */
class ServiceAccountTokens implements GcsAccessTokens
{
    public const string SCOPE = 'https://www.googleapis.com/auth/devstorage.read_write';

    public function __construct(
        private readonly Egress $egress,
        private readonly CacheFactory $cache,
        private readonly StringEncrypter $encrypter,
    ) {}

    public function token(GcpServiceAccount $account): string
    {
        $key = $this->cacheKey($account);
        $cached = $this->store()->get($key);

        if (is_string($cached)) {
            try {
                return $this->encrypter->decryptString($cached);
            } catch (Throwable) {
                // An unreadable entry (rotated APP_KEY) is just a miss.
            }
        }

        [$token, $expiresIn] = $this->exchange($account);
        $ttl = $expiresIn - 60;

        if ($ttl > 0) {
            $this->store()->put($key, $this->encrypter->encryptString($token), $ttl);
        }

        return $token;
    }

    public function forget(GcpServiceAccount $account): void
    {
        $this->store()->forget($this->cacheKey($account));
    }

    /**
     * The signed JWT assertion for an account (public for tests).
     */
    public function assertion(GcpServiceAccount $account, int $issuedAt): string
    {
        $header = ['alg' => 'RS256', 'typ' => 'JWT'];

        if ($account->privateKeyId !== null) {
            $header['kid'] = $account->privateKeyId;
        }

        $claims = [
            'iss' => $account->clientEmail,
            'scope' => self::SCOPE,
            'aud' => $this->tokenUri(),
            'iat' => $issuedAt,
            'exp' => $issuedAt + 3600,
        ];

        $input = self::base64Url((string) json_encode($header)).'.'.self::base64Url((string) json_encode($claims, JSON_UNESCAPED_SLASHES));
        $key = openssl_pkey_get_private($account->privateKey);

        if ($key === false || ! openssl_sign($input, $signature, $key, OPENSSL_ALGO_SHA256) || ! is_string($signature)) {
            throw DestinationRefused::configuration('The service-account private key could not sign the token request.');
        }

        return $input.'.'.self::base64Url($signature);
    }

    /**
     * @return array{string, int}
     */
    private function exchange(GcpServiceAccount $account): array
    {
        $uri = $this->tokenUri();
        $assertion = $this->assertion($account, Carbon::now()->getTimestamp());
        $body = http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $assertion,
        ], '', '&', PHP_QUERY_RFC3986);

        $secrets = [$account->privateKey, $assertion];
        $response = $this->egress->send('POST', $uri, [], $body, 'application/x-www-form-urlencoded', $secrets);

        if (! $response->successful()) {
            $error = $response->json('error');
            $error = is_string($error) && preg_match('/^[a-z_]{1,64}$/', $error) === 1 ? $error : null;

            if (in_array($response->status(), [400, 401, 403], true) && $error !== null && $error !== 'invalid_request') {
                throw DestinationRefused::authentication("Google refused the service-account key ({$error}). The key may be deleted, disabled or for another project.");
            }

            throw $this->egress->failure($response, 'The Google token endpoint', $secrets, $error === null ? '' : "({$error})");
        }

        $token = $response->json('access_token');
        $expiresIn = $response->json('expires_in');

        if (! is_string($token) || $token === '') {
            throw new StreamDeliveryFailed('The Google token endpoint answered without an access token.');
        }

        return [$token, is_int($expiresIn) ? $expiresIn : 3600];
    }

    private function tokenUri(): string
    {
        return Config::string('siem.gcs.token_uri') ?? 'https://oauth2.googleapis.com/token';
    }

    private function cacheKey(GcpServiceAccount $account): string
    {
        return 'siem:gcs-token:'.hash('sha256', $account->clientEmail.'|'.($account->privateKeyId ?? '').'|'.hash('sha256', $account->privateKey));
    }

    private function store(): Cache
    {
        return $this->cache->store(Config::string('siem.credentials_cache.store'));
    }

    private static function base64Url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
