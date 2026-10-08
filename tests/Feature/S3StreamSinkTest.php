<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Enums\FailureKind;
use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Sinks\DestinationRouter;
use Cbox\LaravelSiem\Sinks\S3StreamSink;
use Cbox\LaravelSiem\Support\Aws\SigV4Signer;
use Cbox\LaravelSiem\ValueObjects\AwsCredentials;
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
function s3Target(array $options = [], string $endpoint = 'https://s3.eu-west-1.amazonaws.com'): StreamTarget
{
    return new StreamTarget('s3', $endpoint, [
        'destination' => 's3',
        'secret' => 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'bucket' => 'acme-audit-logs',
        'region' => 'eu-west-1',
        'prefix' => 'cbox/audit',
        'access_key_id' => 'AKIAIOSFODNN7EXAMPLE',
        ...$options,
    ]);
}

/**
 * Re-derive the Authorization header the request should carry, from what was
 * actually sent — proving the signature covers this exact URL, payload hash,
 * date and signed headers.
 *
 * @param  list<string>  $signed  header names that were signed (besides host/x-amz-date)
 */
function expectedS3Authorization(Request $request, string $accessKeyId, string $secret, string $region, array $signed, ?string $token = null): string
{
    $headers = [];
    foreach ($signed as $name) {
        $headers[$name] = $request->header($name)[0];
    }

    return (new SigV4Signer)->sign(
        'PUT', $request->url(), $headers, $request->header('x-amz-content-sha256')[0],
        new AwsCredentials($accessKeyId, $secret, $token), $region, 's3',
        new DateTimeImmutable('2026-10-08T14:03:07Z'),
    )['Authorization'];
}

it('PUTs one gzip NDJSON object per batch under a time-partitioned key, SigV4-signed', function (): void {
    Http::fake(['*' => Http::response('', 200)]);

    app(DestinationRouter::class)->send(['{"id":"evt_1"}', '{"id":"evt_2"}'], s3Target());

    Http::assertSentCount(1);
    Http::assertSent(function (Request $request): bool {
        $body = $request->body();

        expect($request->method())->toBe('PUT')
            ->and($request->url())->toMatch('#^https://acme-audit-logs\.s3\.eu-west-1\.amazonaws\.com/cbox/audit/2026/10/08/14/[0-9a-z]{26}\.ndjson\.gz$#')
            ->and(gzdecode($body))->toBe("{\"id\":\"evt_1\"}\n{\"id\":\"evt_2\"}\n")
            ->and($request->header('Content-Type')[0])->toBe('application/gzip')
            ->and($request->header('x-amz-content-sha256')[0])->toBe(hash('sha256', $body))
            ->and($request->header('X-Amz-Date')[0])->toBe('20261008T140307Z')
            ->and($request->header('Authorization')[0])->toStartWith('AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261008/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=')
            ->and($request->header('Authorization')[0])->toBe(expectedS3Authorization(
                $request, 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'eu-west-1', ['x-amz-content-sha256'],
            ));

        return true;
    });
});

it('writes plain NDJSON when gzip is off', function (): void {
    Http::fake(['*' => Http::response('', 200)]);

    (app(S3StreamSink::class))->send(['{"id":"evt_1"}'], s3Target(['gzip' => false, 'prefix' => null]));

    Http::assertSent(fn (Request $request): bool => preg_match('#^https://acme-audit-logs\.s3\.eu-west-1\.amazonaws\.com/2026/10/08/14/[0-9a-z]{26}\.ndjson$#', $request->url()) === 1
        && $request->body() === "{\"id\":\"evt_1\"}\n"
        && $request->header('Content-Type')[0] === 'application/x-ndjson');
});

it('requests server-side encryption with a KMS key, and signs those headers', function (): void {
    Http::fake(['*' => Http::response('', 200)]);

    app(S3StreamSink::class)->send(['{"id":"evt_1"}'], s3Target(['sse' => 'aws:kms', 'kms_key_id' => 'alias/audit-logs']));

    Http::assertSent(function (Request $request): bool {
        expect($request->header('x-amz-server-side-encryption')[0])->toBe('aws:kms')
            ->and($request->header('x-amz-server-side-encryption-aws-kms-key-id')[0])->toBe('alias/audit-logs')
            ->and($request->header('Authorization')[0])->toContain('SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id,')
            ->and($request->header('Authorization')[0])->toBe(expectedS3Authorization(
                $request, 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'eu-west-1',
                ['x-amz-content-sha256', 'x-amz-server-side-encryption', 'x-amz-server-side-encryption-aws-kms-key-id'],
            ));

        return true;
    });
});

it('uses path-style addressing on an S3-compatible endpoint (MinIO, R2)', function (): void {
    Http::fake(['*' => Http::response('', 200)]);

    app(S3StreamSink::class)->send(['{"id":"evt_1"}'], s3Target(['region' => 'auto'], 'https://0123abcd.r2.cloudflarestorage.com'));

    Http::assertSent(fn (Request $request): bool => str_starts_with($request->url(), 'https://0123abcd.r2.cloudflarestorage.com/acme-audit-logs/cbox/audit/2026/10/08/14/')
        && str_contains($request->header('Authorization')[0], '/20261008/auto/s3/aws4_request'));
});

it('uses path-style for a dotted bucket on AWS (its virtual host would not match the certificate)', function (): void {
    Http::fake(['*' => Http::response('', 200)]);

    app(S3StreamSink::class)->send(['{"id":"evt_1"}'], s3Target(['bucket' => 'audit.acme.example']));

    Http::assertSent(fn (Request $request): bool => str_starts_with($request->url(), 'https://s3.eu-west-1.amazonaws.com/audit.acme.example/cbox/audit/'));
});

it('maps refused credentials to an authentication refusal and a missing bucket to a configuration one', function (int $status, string $code, FailureKind $kind): void {
    Http::fake(['*' => Http::response("<?xml version=\"1.0\"?><Error><Code>{$code}</Code><Message>nope</Message></Error>", $status)]);

    try {
        app(S3StreamSink::class)->send(['{"id":"evt_1"}'], s3Target());
        $this->fail('expected a refusal');
    } catch (DestinationRefused $e) {
        expect($e->kind)->toBe($kind)
            ->and($e->getMessage())->toContain($code)
            ->and($e->getMessage())->not->toContain('wJalrXUtnFEMI');
    }
})->with([
    'access denied' => [403, 'AccessDenied', FailureKind::Authentication],
    'bad key' => [403, 'InvalidAccessKeyId', FailureKind::Authentication],
    'bad signature' => [403, 'SignatureDoesNotMatch', FailureKind::Authentication],
    'no bucket' => [404, 'NoSuchBucket', FailureKind::Configuration],
    'wrong region' => [301, 'PermanentRedirect', FailureKind::Configuration],
    'wrong region header' => [400, 'AuthorizationHeaderMalformed', FailureKind::Configuration],
]);

it('treats throttling and server errors as transient', function (int $status, string $code): void {
    Http::fake(['*' => Http::response("<Error><Code>{$code}</Code></Error>", $status)]);

    expect(fn () => app(S3StreamSink::class)->send(['{"id":"evt_1"}'], s3Target()))
        ->toThrow(fn (StreamDeliveryFailed $e) => expect($e)->not->toBeInstanceOf(DestinationRefused::class));
})->with([[503, 'SlowDown'], [500, 'InternalError']]);
