<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Exceptions;

use RuntimeException;

/**
 * A stream endpoint URL was rejected by the SSRF guard (it resolves to a
 * loopback/private/link-local/metadata/reserved address, uses a disallowed
 * scheme, or embeds credentials). The delivery is refused; nothing is sent.
 */
class UnsafeStreamUrl extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self("Unsafe stream endpoint URL: {$reason}");
    }
}
