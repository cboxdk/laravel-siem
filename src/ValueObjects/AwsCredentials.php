<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\ValueObjects;

use DateTimeImmutable;
use SensitiveParameter;

/**
 * An AWS credential set for SigV4 signing: a long-lived access key, or the
 * short-lived triple (with `sessionToken` and `expiresAt`) an STS `AssumeRole`
 * returns. Held in memory only; `__debugInfo` hides the secret parts so a dump or
 * a log line never shows them.
 */
readonly class AwsCredentials
{
    public function __construct(
        public string $accessKeyId = '',
        #[SensitiveParameter] public string $secretAccessKey = '',
        #[SensitiveParameter] public ?string $sessionToken = null,
        public ?DateTimeImmutable $expiresAt = null,
    ) {}

    /**
     * @return array<string, string|null>
     */
    public function __debugInfo(): array
    {
        return [
            'accessKeyId' => $this->accessKeyId,
            'secretAccessKey' => '[redacted]',
            'sessionToken' => $this->sessionToken === null ? null : '[redacted]',
            'expiresAt' => $this->expiresAt?->format(DATE_ATOM),
        ];
    }
}
