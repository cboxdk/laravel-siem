<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Enums;

/**
 * Server-side encryption requested on every object an S3 stream writes (the
 * `x-amz-server-side-encryption` header). Buckets encrypt with SSE-S3 by default;
 * set this to require a specific mode or a customer-managed KMS key.
 */
enum S3Encryption: string
{
    case Aes256 = 'AES256';
    case Kms = 'aws:kms';
}
