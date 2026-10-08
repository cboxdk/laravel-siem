<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use SensitiveParameter;

/**
 * Removes a stream's secret from any string before it is logged or persisted in an
 * error / dead-letter payload. Delivery errors come from the transport and should
 * not contain the token, but this is the belt-and-braces guarantee that a rotated
 * URL, a verbose client, or a future change can never leak it into `last_error`.
 */
class SecretScrubber
{
    private const string PLACEHOLDER = '[redacted-secret]';

    public function scrub(string $message, #[SensitiveParameter] ?string $secret): string
    {
        if ($secret !== null && $secret !== '') {
            $message = str_replace($secret, self::PLACEHOLDER, $message);
        }

        return $message;
    }

    /**
     * Scrub several secrets at once (an API key and the token it was exchanged
     * for, a key file and its private key, …). Longest first, so a secret that
     * contains another is removed whole.
     *
     * @param  iterable<string|null>  $secrets
     */
    public function scrubAll(string $message, #[SensitiveParameter] iterable $secrets): string
    {
        $values = [];

        foreach ($secrets as $secret) {
            if ($secret !== null && $secret !== '') {
                $values[] = $secret;
            }
        }

        usort($values, static fn (string $a, string $b): int => strlen($b) <=> strlen($a));

        foreach ($values as $value) {
            $message = $this->scrub($message, $value);
        }

        return $message;
    }
}
