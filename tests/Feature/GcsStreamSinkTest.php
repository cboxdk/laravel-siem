<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Enums\FailureKind;
use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Sinks\DestinationRouter;
use Cbox\LaravelSiem\Sinks\GcsStreamSink;
use Cbox\LaravelSiem\Support\Gcp\ServiceAccountTokens;
use Cbox\LaravelSiem\Tests\Fixtures\ServiceAccountKey;
use Cbox\Siem\ValueObjects\StreamTarget;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;

beforeEach(function (): void {
    config(['siem.http.verify_url' => false]);
    Carbon::setTestNow('2026-10-08 14:03:07');
});

afterEach(fn () => Carbon::setTestNow());

/**
 * @param  array<string, scalar|null>  $options
 */
function gcsTarget(array $options = [], ?string $key = null): StreamTarget
{
    return new StreamTarget('gcs', 'https://storage.googleapis.com', [
        'destination' => 'gcs',
        'secret' => $key ?? ServiceAccountKey::json(),
        'bucket' => 'acme-audit-logs',
        'prefix' => 'cbox/audit',
        ...$options,
    ]);
}

function fakeGoogle(int $uploadStatus = 200, string $uploadBody = '{}'): void
{
    Http::fake([
        'oauth2.googleapis.com/*' => Http::response(['access_token' => 'ya29.test-access-token', 'expires_in' => 3599, 'token_type' => 'Bearer']),
        'storage.googleapis.com/*' => Http::response($uploadBody, $uploadStatus),
    ]);
}

/**
 * @return array<string, mixed>
 */
function jwtPart(string $jwt, int $index): array
{
    $decoded = json_decode((string) base64_decode(strtr(explode('.', $jwt)[$index], '-_', '+/'), true), true);

    return is_array($decoded) ? $decoded : [];
}

it('exchanges a signed RS256 JWT for an access token at Google\'s token endpoint', function (): void {
    fakeGoogle();

    app(GcsStreamSink::class)->send(['{"id":"evt_1"}'], gcsTarget());

    $token = Http::recorded(fn (Request $request): bool => str_contains($request->url(), 'oauth2.googleapis.com'))->first()[0];
    parse_str($token->body(), $form);
    $jwt = is_string($form['assertion'] ?? null) ? $form['assertion'] : '';
    [$header, $claims, $signature] = explode('.', $jwt);

    expect($token->url())->toBe('https://oauth2.googleapis.com/token')
        ->and($form['grant_type'])->toBe('urn:ietf:params:oauth:grant-type:jwt-bearer')
        ->and(jwtPart($jwt, 0))->toBe(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'kid-123'])
        ->and(jwtPart($jwt, 1))->toBe([
            'iss' => 'siem-writer@acme-audit.iam.gserviceaccount.com',
            'scope' => ServiceAccountTokens::SCOPE,
            'aud' => 'https://oauth2.googleapis.com/token',
            'iat' => 1791468187,
            'exp' => 1791468187 + 3600,
        ])
        // The signature verifies with the key pair's PUBLIC half — a real RS256.
        ->and(openssl_verify($header.'.'.$claims, (string) base64_decode(strtr($signature, '-_', '+/')), ServiceAccountKey::publicKey(), OPENSSL_ALGO_SHA256))->toBe(1);
});

it('uploads one gzip NDJSON object per batch with the bearer token', function (): void {
    fakeGoogle();

    app(DestinationRouter::class)->send(['{"id":"evt_1"}', '{"id":"evt_2"}'], gcsTarget());

    $upload = Http::recorded(fn (Request $request): bool => str_contains($request->url(), 'storage.googleapis.com'))->first()[0];
    parse_str((string) parse_url($upload->url(), PHP_URL_QUERY), $query);

    expect($upload->method())->toBe('POST')
        ->and($upload->url())->toStartWith('https://storage.googleapis.com/upload/storage/v1/b/acme-audit-logs/o?uploadType=media&name=')
        ->and($query['name'])->toMatch('#^cbox/audit/2026/10/08/14/[0-9a-z]{26}\.ndjson\.gz$#')
        ->and($upload->header('Authorization')[0])->toBe('Bearer ya29.test-access-token')
        ->and($upload->header('Content-Type')[0])->toBe('application/gzip')
        ->and(gzdecode($upload->body()))->toBe("{\"id\":\"evt_1\"}\n{\"id\":\"evt_2\"}\n");
});

it('caches the access token across batches', function (): void {
    fakeGoogle();

    app(GcsStreamSink::class)->send(['{"id":"evt_1"}'], gcsTarget());
    app(GcsStreamSink::class)->send(['{"id":"evt_2"}'], gcsTarget());

    expect(Http::recorded(fn (Request $request): bool => str_contains($request->url(), 'oauth2.googleapis.com')))->toHaveCount(1)
        ->and(Http::recorded(fn (Request $request): bool => str_contains($request->url(), 'storage.googleapis.com')))->toHaveCount(2);
});

it('ignores the key file\'s own token_uri, so a crafted key cannot redirect the exchange', function (): void {
    fakeGoogle();

    app(GcsStreamSink::class)->send(['{"id":"evt_1"}'], gcsTarget(key: ServiceAccountKey::json(tokenUri: 'https://attacker.example/token')));

    Http::assertNotSent(fn (Request $request): bool => str_contains($request->url(), 'attacker.example'));
    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://oauth2.googleapis.com/token');
});

it('refuses a key Google rejects, without leaking the key', function (): void {
    Http::fake(['oauth2.googleapis.com/*' => Http::response(['error' => 'invalid_grant', 'error_description' => 'Invalid JWT Signature.'], 400)]);

    try {
        app(GcsStreamSink::class)->send(['{"id":"evt_1"}'], gcsTarget());
        $this->fail('expected a refusal');
    } catch (DestinationRefused $e) {
        expect($e->kind)->toBe(FailureKind::Authentication)
            ->and($e->getMessage())->toContain('invalid_grant')
            ->and($e->getMessage())->not->toContain('PRIVATE KEY');
    }

    Http::assertNotSent(fn (Request $request): bool => str_contains($request->url(), 'storage.googleapis.com'));
});

it('maps upload refusals: 401 drops the token, 403 is a permission, 404 a missing bucket', function (int $status, FailureKind $kind, string $phrase): void {
    fakeGoogle($status, (string) json_encode(['error' => ['code' => $status, 'message' => 'nope']]));

    expect(fn () => app(GcsStreamSink::class)->send(['{"id":"evt_1"}'], gcsTarget()))
        ->toThrow(function (DestinationRefused $e) use ($kind, $phrase): void {
            expect($e->kind)->toBe($kind)
                ->and($e->getMessage())->toContain($phrase)
                ->and($e->getMessage())->not->toContain('ya29.test-access-token');
        });
})->with([
    [401, FailureKind::Authentication, 'refused the access token'],
    [403, FailureKind::Authentication, 'roles/storage.objectCreator'],
    [404, FailureKind::Configuration, 'has no bucket'],
]);

it('re-exchanges the key after a 401 dropped the cached token', function (): void {
    $uploads = 0;
    Http::fake(function (Request $request) use (&$uploads) {
        if (str_contains($request->url(), 'oauth2.googleapis.com')) {
            return Http::response(['access_token' => 'ya29.token', 'expires_in' => 3599]);
        }

        return ++$uploads === 1 ? Http::response('{}', 401) : Http::response('{}', 200);
    });

    expect(fn () => app(GcsStreamSink::class)->send(['{"id":"evt_1"}'], gcsTarget()))->toThrow(DestinationRefused::class);
    app(GcsStreamSink::class)->send(['{"id":"evt_1"}'], gcsTarget());

    expect(Http::recorded(fn (Request $request): bool => str_contains($request->url(), 'oauth2.googleapis.com')))->toHaveCount(2);
});

it('treats 429 and 5xx from storage as transient', function (int $status): void {
    fakeGoogle($status);

    expect(fn () => app(GcsStreamSink::class)->send(['{"id":"evt_1"}'], gcsTarget()))
        ->toThrow(fn (StreamDeliveryFailed $e) => expect($e)->not->toBeInstanceOf(DestinationRefused::class));
})->with([429, 503]);
