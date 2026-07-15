<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Testing;

use Cbox\LaravelSiem\Sinks\HttpStreamSink;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

/**
 * Programs Laravel's HTTP fake for the {@see HttpStreamSink}
 * so its framing, auth, TLS posture, and SSRF handling can be asserted without a
 * real endpoint. After programming a response, use `Http::assertSent(...)` /
 * `Http::assertNothingSent()` as usual to inspect what would have gone on the wire.
 */
class FakeHttpTransport
{
    /**
     * The destination accepts everything (HTTP 200).
     */
    public static function accepting(): void
    {
        Http::fake(['*' => Http::response('', 200)]);
    }

    /**
     * The destination rejects everything with a server error.
     */
    public static function rejecting(int $status = 500): void
    {
        Http::fake(['*' => Http::response('', $status)]);
    }

    /**
     * The destination is unreachable (a transport-level connection failure).
     */
    public static function unreachable(): void
    {
        Http::fake(fn () => throw new ConnectionException('fake transport: connection failed'));
    }
}
