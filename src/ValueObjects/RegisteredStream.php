<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\ValueObjects;

use Cbox\LaravelSiem\Models\LogStream;

/**
 * The result of registering a stream: the persisted {@see LogStream} plus the
 * plaintext `secret` revealed EXACTLY ONCE at creation. The model stores only the
 * ciphertext, so this is the caller's single opportunity to capture a
 * package-generated HMAC key (a caller-supplied HEC/bearer token is echoed back
 * once for symmetry). After this object is discarded the plaintext is gone.
 */
readonly class RegisteredStream
{
    public function __construct(
        public LogStream $stream,
        public ?string $secret,
    ) {}
}
