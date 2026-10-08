<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Contracts;

use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\ValueObjects\GcpServiceAccount;

/**
 * Exchanges a Google service-account key for an OAuth 2.0 access token (the
 * RFC 7523 JWT-bearer grant) and caches it until shortly before it expires.
 */
interface GcsAccessTokens
{
    /**
     * @throws DestinationRefused when Google refuses the key
     * @throws StreamDeliveryFailed on a transient failure
     */
    public function token(GcpServiceAccount $account): string;

    /**
     * Drop the cached token (after the storage API rejected it).
     */
    public function forget(GcpServiceAccount $account): void;
}
