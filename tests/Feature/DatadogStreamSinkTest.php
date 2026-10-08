<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Enums\FailureKind;
use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Sinks\DatadogStreamSink;
use Cbox\LaravelSiem\Sinks\DestinationRouter;
use Cbox\LaravelSiem\Testing\FakeHttpTransport;
use Cbox\LaravelSiem\ValueObjects\Options\DatadogOptions;
use Cbox\Siem\ValueObjects\StreamTarget;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

beforeEach(fn () => config(['siem.http.verify_url' => false, 'app.name' => 'acme-id', 'app.url' => 'https://id.acme.example']));

/**
 * @param  array<string, scalar|null>  $options
 */
function datadogTarget(array $options = [], string $endpoint = 'https://http-intake.logs.datadoghq.eu/api/v2/logs'): StreamTarget
{
    return new StreamTarget('dd', $endpoint, [
        'destination' => 'datadog',
        'secret' => 'dd-api-key-0123456789abcdef',
        'site' => 'datadoghq.eu',
        ...$options,
    ]);
}

/**
 * @return list<array<string, mixed>>
 */
function datadogEntries(Request $request): array
{
    $json = json_decode((string) gzdecode($request->body()), true);

    return is_array($json) ? array_values($json) : [];
}

it('posts gzip-compressed Datadog log entries to the site intake with the API key header', function (): void {
    FakeHttpTransport::accepting();

    app(DestinationRouter::class)->send(
        ['{"id":"evt_1","action":"user-login"}', '{"id":"evt_2","action":"role-granted"}'],
        datadogTarget(['service' => 'cbox-id', 'source' => 'cbox', 'tags' => 'env:prod,team:security', 'hostname' => 'id.cbox.example']),
    );

    Http::assertSentCount(1);
    Http::assertSent(function (Request $request): bool {
        return $request->method() === 'POST'
            && $request->url() === 'https://http-intake.logs.datadoghq.eu/api/v2/logs'
            && $request->header('DD-API-KEY')[0] === 'dd-api-key-0123456789abcdef'
            && $request->header('Content-Encoding')[0] === 'gzip'
            && $request->header('Content-Type')[0] === 'application/json'
            && datadogEntries($request) === [
                ['ddsource' => 'cbox', 'ddtags' => 'env:prod,team:security', 'hostname' => 'id.cbox.example', 'service' => 'cbox-id', 'message' => '{"id":"evt_1","action":"user-login"}'],
                ['ddsource' => 'cbox', 'ddtags' => 'env:prod,team:security', 'hostname' => 'id.cbox.example', 'service' => 'cbox-id', 'message' => '{"id":"evt_2","action":"role-granted"}'],
            ];
    });
});

it('defaults service to the app name and hostname to the app URL host', function (): void {
    FakeHttpTransport::accepting();

    (new DatadogStreamSink)->send(['{"id":"evt_1"}'], datadogTarget());

    Http::assertSent(fn (Request $request): bool => datadogEntries($request) === [
        ['ddsource' => 'cbox', 'hostname' => 'id.acme.example', 'service' => 'acme-id', 'message' => '{"id":"evt_1"}'],
    ]);
});

it('derives the intake host for every Datadog site', function (string $site, string $url): void {
    expect(DatadogOptions::fromArray(['site' => $site])->defaultEndpoint())->toBe($url);
})->with([
    ['datadoghq.com', 'https://http-intake.logs.datadoghq.com/api/v2/logs'],
    ['datadoghq.eu', 'https://http-intake.logs.datadoghq.eu/api/v2/logs'],
    ['us3.datadoghq.com', 'https://http-intake.logs.us3.datadoghq.com/api/v2/logs'],
    ['us5.datadoghq.com', 'https://http-intake.logs.us5.datadoghq.com/api/v2/logs'],
    ['ap1.datadoghq.com', 'https://http-intake.logs.ap1.datadoghq.com/api/v2/logs'],
    ['ddog-gov.com', 'https://http-intake.logs.ddog-gov.com/api/v2/logs'],
]);

it('never puts more than 1000 entries in one request', function (): void {
    FakeHttpTransport::accepting();

    $records = array_map(static fn (int $i): string => '{"id":"evt_'.$i.'"}', range(1, 2500));
    (new DatadogStreamSink)->send($records, datadogTarget());

    $sizes = [];
    Http::assertSent(function (Request $request) use (&$sizes): bool {
        $sizes[] = count(datadogEntries($request));

        return true;
    });

    expect($sizes)->toBe([1000, 1000, 500]);
});

it('never puts more than 5 MB of uncompressed JSON in one request', function (): void {
    FakeHttpTransport::accepting();

    // 12 records of ~900 KB each: ~10.8 MB in all, so at least three requests.
    $records = array_map(static fn (int $i): string => '{"id":"evt_'.$i.'","blob":"'.str_repeat('x', 900_000).'"}', range(1, 12));
    (new DatadogStreamSink)->send($records, datadogTarget());

    $requests = 0;
    $entries = 0;
    Http::assertSent(function (Request $request) use (&$requests, &$entries): bool {
        $json = (string) gzdecode($request->body());
        expect(strlen($json))->toBeLessThanOrEqual(DatadogStreamSink::MAX_PAYLOAD_BYTES);
        $requests++;
        $entries += count(datadogEntries($request));

        return true;
    });

    expect($requests)->toBe(3)->and($entries)->toBe(12);
});

it('maps 401/403 to an authentication refusal, scrubbed of the key', function (int $status): void {
    FakeHttpTransport::refusingCredentials($status);

    try {
        (new DatadogStreamSink)->send(['{"id":"evt_1"}'], datadogTarget());
        $this->fail('expected a refusal');
    } catch (DestinationRefused $e) {
        expect($e->kind)->toBe(FailureKind::Authentication)
            ->and($e->getMessage())->not->toContain('dd-api-key-0123456789abcdef');
    }
})->with([401, 403]);

it('treats 429 and 5xx as transient', function (int $status): void {
    FakeHttpTransport::rejecting($status);

    expect(fn () => (new DatadogStreamSink)->send(['{"id":"evt_1"}'], datadogTarget()))
        ->toThrow(fn (StreamDeliveryFailed $e) => expect($e)->not->toBeInstanceOf(DestinationRefused::class));
})->with([429, 500, 503]);

it('refuses a stream without an API key as a configuration problem', function (): void {
    Http::fake();

    expect(fn () => (new DatadogStreamSink)->send(['{"id":"evt_1"}'], datadogTarget(['secret' => null])))
        ->toThrow(fn (DestinationRefused $e) => expect($e->kind)->toBe(FailureKind::Configuration));

    Http::assertNothingSent();
});
