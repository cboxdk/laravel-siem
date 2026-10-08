<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\ValueObjects;

use Cbox\LaravelSiem\Exceptions\InvalidStreamConfiguration;
use SensitiveParameter;

/**
 * The parts of a Google service-account JSON key the GCS sink needs: the account
 * email (the JWT issuer), the PEM private key that signs the token request, and
 * its key id. The key file's own `token_uri` is deliberately IGNORED — the token
 * exchange always goes to the configured Google endpoint (`siem.gcs.token_uri`),
 * so a crafted key file cannot point the platform's egress at an address of its
 * choosing. `__debugInfo` hides the private key.
 */
readonly class GcpServiceAccount
{
    public function __construct(
        public string $clientEmail = '',
        #[SensitiveParameter] public string $privateKey = '',
        public ?string $privateKeyId = null,
    ) {}

    /**
     * Parse and validate a service-account key file. Messages never echo it.
     *
     * @throws InvalidStreamConfiguration
     */
    public static function fromJson(#[SensitiveParameter] ?string $json): self
    {
        if ($json === null || trim($json) === '') {
            throw InvalidStreamConfiguration::for('secret', 'A Google Cloud Storage stream needs a service-account JSON key.');
        }

        $data = json_decode($json, true);

        if (! is_array($data) || ($data['type'] ?? null) !== 'service_account') {
            throw InvalidStreamConfiguration::for('secret', 'The secret must be a service-account JSON key (type "service_account").');
        }

        $email = $data['client_email'] ?? null;
        $key = $data['private_key'] ?? null;
        $keyId = $data['private_key_id'] ?? null;

        if (! is_string($email) || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw InvalidStreamConfiguration::for('secret', 'The service-account key has no valid client_email.');
        }

        if (! is_string($key) || openssl_pkey_get_private($key) === false) {
            throw InvalidStreamConfiguration::for('secret', 'The service-account key has no usable private_key.');
        }

        return new self($email, $key, is_string($keyId) && $keyId !== '' ? $keyId : null);
    }

    /**
     * @return array<string, string|null>
     */
    public function __debugInfo(): array
    {
        return [
            'clientEmail' => $this->clientEmail,
            'privateKey' => '[redacted]',
            'privateKeyId' => $this->privateKeyId,
        ];
    }
}
