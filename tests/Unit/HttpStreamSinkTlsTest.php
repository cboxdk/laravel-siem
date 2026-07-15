<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Sinks\HttpStreamSink;
use Illuminate\Support\Facades\Log;

it('does not configure the client to skip TLS verification by default', function (): void {
    // No `verify` key means Guzzle's default (verification ON) is used — the sink
    // never silently disables certificate checking.
    expect((new HttpStreamSink)->tlsOptions())->toBe([]);
});

it('only disables TLS verification when explicitly configured, and logs loudly', function (): void {
    config(['siem.http.tls_verify' => false]);
    Log::spy();

    expect((new HttpStreamSink)->tlsOptions())->toBe(['verify' => false]);

    Log::shouldHaveReceived('warning')->once();
});
