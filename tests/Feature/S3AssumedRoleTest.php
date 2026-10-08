<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Enums\FailureKind;
use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Sinks\S3StreamSink;
use Cbox\LaravelSiem\Support\Aws\SigV4Signer;
use Cbox\LaravelSiem\ValueObjects\AwsCredentials;
use Cbox\Siem\ValueObjects\StreamTarget;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;

beforeEach(function (): void {
    config([
        'siem.http.verify_url' => false,
        'siem.aws.access_key_id' => 'AKIAPLATFORMEXAMPLE',
        'siem.aws.secret_access_key' => 'platform-secret-access-key',
    ]);
    Carbon::setTestNow('2026-10-08 14:03:07');
});

afterEach(fn () => Carbon::setTestNow());

function roleTarget(): StreamTarget
{
    return new StreamTarget('s3-role', 'https://s3.eu-west-1.amazonaws.com', [
        'destination' => 's3',
        'secret' => null,
        'bucket' => 'acme-audit-logs',
        'region' => 'eu-west-1',
        'role_arn' => 'arn:aws:iam::123456789012:role/cbox-log-writer',
        'external_id' => 'ext-0f3a9c',
    ]);
}

function stsResponse(): string
{
    return <<<'XML'
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIATEMPEXAMPLE</AccessKeyId>
      <SecretAccessKey>temp-secret-access-key</SecretAccessKey>
      <SessionToken>temp-session-token+/=</SessionToken>
      <Expiration>2026-10-08T15:03:07Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>
XML;
}

it('assumes the stream role with the platform identity, then writes with the temporary credentials', function (): void {
    Http::fake([
        'sts.amazonaws.com/*' => Http::response(stsResponse(), 200),
        '*' => Http::response('', 200),
    ]);

    app(S3StreamSink::class)->send(['{"id":"evt_1"}'], roleTarget());

    $sts = Http::recorded(fn (Request $request): bool => str_contains($request->url(), 'sts.amazonaws.com'))->first()[0];
    parse_str($sts->body(), $form);

    expect($sts->method())->toBe('POST')
        ->and($form)->toMatchArray([
            'Action' => 'AssumeRole',
            'RoleArn' => 'arn:aws:iam::123456789012:role/cbox-log-writer',
            'ExternalId' => 'ext-0f3a9c',
            'Version' => '2011-06-15',
        ])
        ->and($sts->header('Authorization')[0])->toBe((new SigV4Signer)->sign(
            'POST', 'https://sts.amazonaws.com/', ['Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8'],
            hash('sha256', $sts->body()), new AwsCredentials('AKIAPLATFORMEXAMPLE', 'platform-secret-access-key'),
            'us-east-1', 'sts', new DateTimeImmutable('2026-10-08T14:03:07Z'),
        )['Authorization']);

    $put = Http::recorded(fn (Request $request): bool => $request->method() === 'PUT')->first()[0];

    expect($put->header('X-Amz-Security-Token')[0])->toBe('temp-session-token+/=')
        ->and($put->header('Authorization')[0])->toStartWith('AWS4-HMAC-SHA256 Credential=ASIATEMPEXAMPLE/20261008/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,');
});

it('caches the assumed-role credentials instead of calling STS for every batch', function (): void {
    Http::fake([
        'sts.amazonaws.com/*' => Http::response(stsResponse(), 200),
        '*' => Http::response('', 200),
    ]);

    app(S3StreamSink::class)->send(['{"id":"evt_1"}'], roleTarget());
    app(S3StreamSink::class)->send(['{"id":"evt_2"}'], roleTarget());

    expect(Http::recorded(fn (Request $request): bool => str_contains($request->url(), 'sts.amazonaws.com')))->toHaveCount(1)
        ->and(Http::recorded(fn (Request $request): bool => $request->method() === 'PUT'))->toHaveCount(2);
});

it('drops cached credentials S3 calls expired, and retries as transient', function (): void {
    $puts = 0;
    Http::fake(function (Request $request) use (&$puts) {
        if (str_contains($request->url(), 'sts.amazonaws.com')) {
            return Http::response(stsResponse(), 200);
        }

        return ++$puts === 1
            ? Http::response('<Error><Code>ExpiredToken</Code></Error>', 400)
            : Http::response('', 200);
    });

    expect(fn () => app(S3StreamSink::class)->send(['{"id":"evt_1"}'], roleTarget()))
        ->toThrow(fn (StreamDeliveryFailed $e) => expect($e)->not->toBeInstanceOf(DestinationRefused::class));

    app(S3StreamSink::class)->send(['{"id":"evt_1"}'], roleTarget());

    expect(Http::recorded(fn (Request $request): bool => str_contains($request->url(), 'sts.amazonaws.com')))->toHaveCount(2);
});

it('refuses when AWS will not let the platform assume the role', function (): void {
    Http::fake(['sts.amazonaws.com/*' => Http::response('<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>', 403)]);

    expect(fn () => app(S3StreamSink::class)->send(['{"id":"evt_1"}'], roleTarget()))
        ->toThrow(function (DestinationRefused $e): void {
            expect($e->kind)->toBe(FailureKind::Authentication)
                ->and($e->getMessage())->toContain('trust policy')
                ->and($e->getMessage())->not->toContain('platform-secret-access-key');
        });

    Http::assertNotSent(fn (Request $request): bool => $request->method() === 'PUT');
});

it('refuses an assumed-role stream when the platform has no AWS identity configured', function (): void {
    config(['siem.aws.access_key_id' => null, 'siem.aws.secret_access_key' => null]);
    Http::fake();

    expect(fn () => app(S3StreamSink::class)->send(['{"id":"evt_1"}'], roleTarget()))
        ->toThrow(fn (DestinationRefused $e) => expect($e->kind)->toBe(FailureKind::Configuration));

    Http::assertNothingSent();
});
