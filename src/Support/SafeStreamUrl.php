<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Cbox\LaravelSiem\Exceptions\UnsafeStreamUrl;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;

/**
 * SSRF gate for outbound stream endpoints. The real guarding — scheme/credential
 * checks, dual-stack resolution, private/reserved/cloud-metadata blocking for
 * IPv4 and IPv6, and DNS pinning — lives in the shared, independently-tested
 * `cboxdk/laravel-ssrf` package. This adapter keeps the package's own on/off
 * toggle so on-prem single-tenant installs can reach an internal collector.
 */
class SafeStreamUrl
{
    public static function isSafe(string $url): bool
    {
        try {
            self::assert($url);

            return true;
        } catch (UnsafeStreamUrl) {
            return false;
        }
    }

    /**
     * @throws UnsafeStreamUrl
     */
    public static function assert(string $url): void
    {
        if (! self::enforced()) {
            return;
        }

        try {
            app(UrlGuard::class)->assertSafe($url);
        } catch (BlockedUrl $e) {
            throw UnsafeStreamUrl::make($e->getMessage());
        }
    }

    /**
     * Validate the URL and return Guzzle options that PIN the connection to the
     * exact IPs just resolved (one resolution, no redirects) — closing the
     * DNS-rebind TOCTOU window between the check and the connect. Empty when
     * enforcement is disabled.
     *
     * @return array<string, mixed>
     *
     * @throws UnsafeStreamUrl
     */
    public static function pinnedOptions(string $url): array
    {
        if (! self::enforced()) {
            return ['allow_redirects' => false];
        }

        try {
            return app(UrlGuard::class)->pinnedOptions($url);
        } catch (BlockedUrl $e) {
            throw UnsafeStreamUrl::make($e->getMessage());
        }
    }

    private static function enforced(): bool
    {
        return config('siem.http.verify_url', true) !== false;
    }
}
