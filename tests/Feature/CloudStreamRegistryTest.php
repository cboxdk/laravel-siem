<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Enums\AuthScheme;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Enums\FailureKind;
use Cbox\LaravelSiem\Exceptions\InvalidStreamConfiguration;
use Cbox\LaravelSiem\Exceptions\UnsafeStreamUrl;
use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\Tests\Fixtures\ServiceAccountKey;
use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Testing\FakeResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

beforeEach(fn () => config(['siem.http.verify_url' => false]));

it('registers a Datadog stream with the site intake as its endpoint and the API key encrypted', function (): void {
    $registered = $this->createLogStream('dd', Destination::Datadog, '', secret: 'dd-api-key', options: [
        'site' => 'datadoghq.eu', 'service' => 'cbox-id', 'tags' => ['env:prod', 'team:sec'],
    ]);

    $stream = LogStream::query()->findOrFail($registered->stream->id);
    $raw = DB::table('log_streams')->where('id', $stream->id)->value('secret');

    expect($stream->endpoint_url)->toBe('https://http-intake.logs.datadoghq.eu/api/v2/logs')
        ->and($stream->auth)->toBe(AuthScheme::None)
        ->and($stream->destinationOptions())->toBe(['site' => 'datadoghq.eu', 'service' => 'cbox-id', 'tags' => 'env:prod,team:sec'])
        ->and($stream->secret)->toBe('dd-api-key')
        ->and($raw)->not->toContain('dd-api-key');
});

it('registers an access-key S3 stream; the key ID is an option, the secret key is encrypted', function (): void {
    $registered = $this->createLogStream('s3', Destination::S3, '', secret: 'aws-secret', options: [
        'bucket' => 'acme-audit-logs', 'region' => 'eu-west-1', 'prefix' => '/cbox/audit/', 'access_key_id' => 'AKIAEXAMPLE1234',
        'sse' => 'AES256',
    ]);

    expect($registered->stream->endpoint_url)->toBe('https://s3.eu-west-1.amazonaws.com')
        ->and($registered->stream->destinationOptions())->toBe([
            'bucket' => 'acme-audit-logs', 'region' => 'eu-west-1', 'prefix' => 'cbox/audit',
            'access_key_id' => 'AKIAEXAMPLE1234', 'sse' => 'AES256', 'gzip' => true,
        ]);
});

it('generates an external ID for an assumed-role S3 stream, and stores no secret', function (): void {
    $registered = $this->createLogStream('s3', Destination::S3, '', options: [
        'bucket' => 'acme-audit-logs', 'region' => 'eu-west-1', 'role_arn' => 'arn:aws:iam::123456789012:role/cbox-log-writer',
    ]);

    expect($registered->stream->secret)->toBeNull()
        ->and($registered->stream->destinationOptions()['external_id'] ?? null)->toMatch('/^[0-9a-f]{32}$/');
});

it('registers an S3-compatible stream on a custom https endpoint', function (): void {
    $registered = $this->createLogStream('r2', Destination::S3, 'https://0123abcd.r2.cloudflarestorage.com/', secret: 's', options: [
        'bucket' => 'audit', 'region' => 'auto', 'access_key_id' => 'abcdef0123456789',
    ]);

    expect($registered->stream->endpoint_url)->toBe('https://0123abcd.r2.cloudflarestorage.com');
});

it('runs a custom S3-compatible endpoint through the SSRF guard', function (): void {
    config(['siem.http.verify_url' => true]);
    app()->instance(Resolver::class, new FakeResolver(['minio.internal.example' => ['10.0.0.12']]));

    $this->createLogStream('minio', Destination::S3, 'https://minio.internal.example', secret: 's', options: [
        'bucket' => 'audit', 'region' => 'us-east-1', 'access_key_id' => 'minioadmin',
    ]);
})->throws(UnsafeStreamUrl::class);

it('registers a GCS stream with a parseable service-account key', function (): void {
    $registered = $this->createLogStream('gcs', Destination::Gcs, '', secret: ServiceAccountKey::json(), options: ['bucket' => 'acme-audit-logs']);

    expect($registered->stream->endpoint_url)->toBe('https://storage.googleapis.com')
        ->and($registered->stream->destinationOptions())->toBe(['bucket' => 'acme-audit-logs', 'gzip' => true]);
});

it('refuses invalid destination settings before storing anything', function (Destination $destination, string $endpoint, ?string $secret, array $options, string $field): void {
    try {
        $this->createLogStream('bad', $destination, $endpoint, secret: $secret, options: $options);
        $this->fail('expected the settings to be refused');
    } catch (InvalidStreamConfiguration $e) {
        expect($e->field)->toBe($field)
            ->and(LogStream::query()->count())->toBe(0);

        if ($secret !== null) {
            expect($e->getMessage())->not->toContain($secret);
        }
    }
})->with([
    'datadog: unknown site' => [Destination::Datadog, '', 'secret-value-zq9', ['site' => 'datadoghq.example'], 'site'],
    'datadog: no api key' => [Destination::Datadog, '', null, ['site' => 'datadoghq.com'], 'secret'],
    'datadog: bad tag' => [Destination::Datadog, '', 'secret-value-zq9', ['tags' => 'env prod'], 'tags'],
    's3: no bucket' => [Destination::S3, '', 'secret-value-zq9', ['region' => 'eu-west-1', 'access_key_id' => 'AKIAEXAMPLE1234'], 'bucket'],
    's3: bad bucket' => [Destination::S3, '', 'secret-value-zq9', ['bucket' => 'Bad_Bucket', 'region' => 'eu-west-1', 'access_key_id' => 'AKIAEXAMPLE1234'], 'bucket'],
    's3: no credentials' => [Destination::S3, '', null, ['bucket' => 'audit', 'region' => 'eu-west-1'], 'access_key_id'],
    's3: both credential modes' => [Destination::S3, '', null, ['bucket' => 'audit', 'region' => 'eu-west-1', 'access_key_id' => 'AKIAEXAMPLE1234', 'role_arn' => 'arn:aws:iam::123456789012:role/x'], 'access_key_id'],
    's3: key without secret' => [Destination::S3, '', null, ['bucket' => 'audit', 'region' => 'eu-west-1', 'access_key_id' => 'AKIAEXAMPLE1234'], 'secret'],
    's3: role with a secret' => [Destination::S3, '', 'leftover-secret', ['bucket' => 'audit', 'region' => 'eu-west-1', 'role_arn' => 'arn:aws:iam::123456789012:role/x'], 'secret'],
    's3: path traversal prefix' => [Destination::S3, '', 'secret-value-zq9', ['bucket' => 'audit', 'region' => 'eu-west-1', 'access_key_id' => 'AKIAEXAMPLE1234', 'prefix' => 'a/../b'], 'prefix'],
    's3: kms key without kms' => [Destination::S3, '', 'secret-value-zq9', ['bucket' => 'audit', 'region' => 'eu-west-1', 'access_key_id' => 'AKIAEXAMPLE1234', 'kms_key_id' => 'alias/x'], 'kms_key_id'],
    's3: plain http endpoint' => [Destination::S3, 'http://minio.example.com', 'secret-value-zq9', ['bucket' => 'audit', 'region' => 'eu-west-1', 'access_key_id' => 'AKIAEXAMPLE1234'], 'endpoint_url'],
    'gcs: not a key file' => [Destination::Gcs, '', '{"type":"authorized_user"}', ['bucket' => 'audit'], 'secret'],
    'gcs: no bucket' => [Destination::Gcs, '', null, [], 'bucket'],
    'http collector with options' => [Destination::GenericJson, 'https://c.example.com', null, ['bucket' => 'x'], 'options'],
]);

it('re-validates and resets the breaker when an operator fixes a stream\'s credentials', function (): void {
    $registered = $this->createLogStream('dd', Destination::Datadog, '', secret: 'old-key', options: ['site' => 'datadoghq.com']);

    $stream = LogStream::query()->findOrFail($registered->stream->id);
    $stream->forceFill([
        'consecutive_failures' => 3,
        'circuit_opened_at' => Carbon::now(),
        'last_failure_kind' => FailureKind::Authentication,
        'last_error' => 'Datadog responded with HTTP 403.',
    ])->save();

    $updated = app(LogStreams::class)->update($stream->id, ['secret' => 'new-key', 'options' => ['site' => 'datadoghq.eu']]);

    expect($updated->secret)->toBe('new-key')
        ->and($updated->stream->endpoint_url)->toBe('https://http-intake.logs.datadoghq.eu/api/v2/logs')
        ->and($updated->stream->consecutive_failures)->toBe(0)
        ->and($updated->stream->circuit_opened_at)->toBeNull()
        ->and($updated->stream->last_failure_kind)->toBeNull()
        ->and($updated->stream->last_error)->toBeNull();
});

it('refuses an update that would leave the settings invalid', function (): void {
    $registered = $this->createLogStream('s3', Destination::S3, '', secret: 's', options: [
        'bucket' => 'audit', 'region' => 'eu-west-1', 'access_key_id' => 'AKIAEXAMPLE1234',
    ]);

    app(LogStreams::class)->update($registered->stream->id, ['options' => ['region' => 'eu-west-1', 'access_key_id' => 'AKIAEXAMPLE1234']]);
})->throws(InvalidStreamConfiguration::class);

it('still lists only the HTTP collectors for a URL-and-token form', function (): void {
    expect(Destination::httpCollectors())->toBe([
        Destination::SplunkHec, Destination::ElasticEcs, Destination::GraylogGelf, Destination::CefHttp, Destination::GenericJson,
    ]);
});
