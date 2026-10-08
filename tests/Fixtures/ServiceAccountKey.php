<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Tests\Fixtures;

use RuntimeException;

/**
 * A real RSA keypair in Google's service-account JSON key shape, generated once
 * per test run — so the GCS token request is signed with a genuine key and its
 * JWT signature is verified with the matching public key, not mocked.
 */
class ServiceAccountKey
{
    /** @var array{private: string, public: string}|null */
    private static ?array $pair = null;

    public static function json(string $email = 'siem-writer@acme-audit.iam.gserviceaccount.com', ?string $tokenUri = null): string
    {
        return (string) json_encode([
            'type' => 'service_account',
            'project_id' => 'acme-audit',
            'private_key_id' => 'kid-123',
            'private_key' => self::pair()['private'],
            'client_email' => $email,
            'client_id' => '1234567890',
            'token_uri' => $tokenUri ?? 'https://oauth2.googleapis.com/token',
        ]);
    }

    public static function publicKey(): string
    {
        return self::pair()['public'];
    }

    public static function privateKey(): string
    {
        return self::pair()['private'];
    }

    /**
     * @return array{private: string, public: string}
     */
    private static function pair(): array
    {
        if (self::$pair !== null) {
            return self::$pair;
        }

        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        if ($key === false || ! openssl_pkey_export($key, $private)) {
            throw new RuntimeException('could not generate a test RSA key');
        }

        $details = openssl_pkey_get_details($key);

        if ($details === false || ! is_string($private) || ! is_string($details['key'] ?? null)) {
            throw new RuntimeException('could not read the test RSA key');
        }

        return self::$pair = ['private' => $private, 'public' => $details['key']];
    }
}
