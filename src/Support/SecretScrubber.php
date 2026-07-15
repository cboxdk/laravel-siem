<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

/**
 * Removes a stream's secret from any string before it is logged or persisted in an
 * error / dead-letter payload. Delivery errors come from the transport and should
 * not contain the token, but this is the belt-and-braces guarantee that a rotated
 * URL, a verbose client, or a future change can never leak it into `last_error`.
 */
class SecretScrubber
{
    private const string PLACEHOLDER = '[redacted-secret]';

    public function scrub(string $message, ?string $secret): string
    {
        if ($secret !== null && $secret !== '') {
            $message = str_replace($secret, self::PLACEHOLDER, $message);
        }

        return $message;
    }
}
