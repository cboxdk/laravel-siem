<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Sinks\HttpStreamSink;
use Cbox\Siem\ValueObjects\StreamTarget;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

// Framing/auth assertions target the sink, not the SSRF guard; disable URL
// verification so the .test endpoints don't need DNS.
beforeEach(fn () => config(['siem.http.verify_url' => false]));

it('ships NDJSON to the Splunk collector event endpoint with the Splunk token', function (): void {
    Http::fake(['*' => Http::response('', 200)]);

    (new HttpStreamSink)->send(
        ['{"event":1}', '{"event":2}'],
        new StreamTarget('splunk', 'https://hec.example.test', [
            'destination' => 'splunk_hec',
            'auth' => 'splunk',
            'secret' => 'hec-token',
            'content_type' => 'application/json',
        ]),
    );

    Http::assertSent(function (Request $request): bool {
        return $request->url() === 'https://hec.example.test/services/collector/event'
            && $request->header('Authorization')[0] === 'Splunk hec-token'
            && $request->body() === "{\"event\":1}\n{\"event\":2}";
    });
});

it('sends a bearer token for a generic JSON destination', function (): void {
    Http::fake(['*' => Http::response('', 200)]);

    (new HttpStreamSink)->send(
        ['{"a":1}'],
        new StreamTarget('json', 'https://collector.example.test/ingest', [
            'destination' => 'generic_json',
            'auth' => 'bearer',
            'secret' => 'bearer-token',
            'content_type' => 'application/json',
        ]),
    );

    Http::assertSent(fn (Request $request): bool => $request->header('Authorization')[0] === 'Bearer bearer-token');
});

it('signs the body with HMAC when the auth scheme is hmac', function (): void {
    Http::fake(['*' => Http::response('', 200)]);

    (new HttpStreamSink)->send(
        ['{"a":1}'],
        new StreamTarget('json', 'https://collector.example.test/ingest', [
            'destination' => 'generic_json',
            'auth' => 'hmac',
            'secret' => 'signing-key',
            'content_type' => 'application/json',
        ]),
    );

    Http::assertSent(function (Request $request): bool {
        $timestamp = $request->header('X-Cbox-Timestamp')[0];
        $expected = 't='.$timestamp.',v1='.hash_hmac('sha256', $timestamp.'.'.$request->body(), 'signing-key');

        return $request->header('X-Cbox-Signature')[0] === $expected;
    });
});

it('never sends the token in a URL query string', function (): void {
    Http::fake(['*' => Http::response('', 200)]);

    (new HttpStreamSink)->send(
        ['{"a":1}'],
        new StreamTarget('json', 'https://collector.example.test/ingest', [
            'destination' => 'generic_json',
            'auth' => 'bearer',
            'secret' => 'bearer-token',
        ]),
    );

    Http::assertSent(fn (Request $request): bool => ! str_contains($request->url(), 'bearer-token'));
});

it('throws a delivery failure (scrubbed) on a non-2xx response', function (): void {
    Http::fake(['*' => Http::response('nope', 503)]);

    expect(fn () => (new HttpStreamSink)->send(
        ['{"a":1}'],
        new StreamTarget('json', 'https://collector.example.test/ingest', [
            'destination' => 'generic_json',
            'auth' => 'bearer',
            'secret' => 'bearer-token',
        ]),
    ))->toThrow(StreamDeliveryFailed::class);
});
