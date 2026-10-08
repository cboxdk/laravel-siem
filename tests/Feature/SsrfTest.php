<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Exceptions\UnsafeStreamUrl;
use Cbox\LaravelSiem\Sinks\HttpStreamSink;
use Cbox\LaravelSiem\Support\SafeStreamUrl;
use Cbox\LaravelSiem\Tests\Fixtures\ServiceAccountKey;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\ValueObjects\StreamTarget;
use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Testing\FakeResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

// The SSRF guard is enabled (its default) for these tests.
beforeEach(fn () => config(['siem.http.verify_url' => true]));

it('refuses to register a stream whose endpoint resolves to a non-public address', function (): void {
    app(LogStreams::class)->create('bad', Destination::GenericJson, 'http://169.254.169.254/collector');
})->throws(UnsafeStreamUrl::class);

it('rejects loopback, private, link-local and metadata endpoints', function (string $url): void {
    expect(SafeStreamUrl::isSafe($url))->toBeFalse();
})->with([
    'http://127.0.0.1/x',
    'http://localhost/x',
    'http://[::1]/x',
    'http://169.254.169.254/latest/meta-data/', // cloud metadata
    'http://10.0.0.5/x',
    'http://192.168.1.1/x',
    'https://user:pass@example.com/x',           // embedded credentials
    'ftp://example.com/x',                        // disallowed scheme
]);

it('aborts a delivery to a private endpoint and puts nothing on the wire', function (): void {
    Http::fake();
    // A hostname that resolves to the metadata address — the guard blocks it and
    // the sink throws before any request is made.
    app()->instance(Resolver::class, new FakeResolver(['evil.example.com' => ['169.254.169.254']]));

    $sink = new HttpStreamSink;
    $target = new StreamTarget('evil', 'https://evil.example.com/collector', ['destination' => 'generic_json']);

    expect(fn () => $sink->send(['{"a":1}'], $target))->toThrow(StreamDeliveryFailed::class);

    Http::assertNothingSent();
});

it('allows a genuinely public endpoint', function (): void {
    expect(SafeStreamUrl::isSafe('https://93.184.216.34/collector'))->toBeTrue();
});

it('aborts a cloud delivery whose endpoint resolves to a private address', function (string $destination, array $options): void {
    Http::fake();
    app()->instance(Resolver::class, new FakeResolver([
        'minio.evil.example' => ['10.0.0.12'],
        'oauth2.googleapis.com' => ['10.0.0.13'],
    ]));

    $target = new StreamTarget('cloud', 'https://minio.evil.example', ['destination' => $destination, ...$options]);

    expect(fn () => app(StreamSink::class)->send(['{"a":1}'], $target))->toThrow(StreamDeliveryFailed::class);

    Http::assertNothingSent();
})->with([
    's3 custom endpoint' => ['s3', ['bucket' => 'audit', 'region' => 'us-east-1', 'access_key_id' => 'minioadmin', 'secret' => 'minio-secret']],
    'datadog proxy' => ['datadog', ['site' => 'datadoghq.com', 'secret' => 'dd-key']],
    'gcs token exchange' => ['gcs', ['bucket' => 'audit', 'secret' => ServiceAccountKey::json()]],
]);
