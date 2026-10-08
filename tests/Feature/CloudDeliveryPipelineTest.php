<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\LaravelSiem\Enums\DeliveryStatus;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Enums\FailureKind;
use Cbox\LaravelSiem\Enums\StreamHealth;
use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\Models\StreamDelivery;
use Cbox\LaravelSiem\SinkStreamTester;
use Cbox\LaravelSiem\Testing\FakeHttpTransport;
use Cbox\LaravelSiem\Tests\Fixtures\EventFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['siem.http.verify_url' => false, 'siem.circuit_breaker.failure_threshold' => 5]);
    Carbon::setTestNow('2026-10-08 14:03:07');
});

afterEach(fn () => Carbon::setTestNow());

function datadogStream(): LogStream
{
    return app(LogStreams::class)->create('dd', Destination::Datadog, '', 'dd-api-key-0123456789', options: ['site' => 'datadoghq.eu'])->stream;
}

it('delivers outbox rows end to end through the real Datadog sink, redacted', function (): void {
    FakeHttpTransport::accepting();
    $stream = $this->createLogStream('dd', Destination::Datadog, '', secret: 'dd-api-key-0123456789', options: ['site' => 'datadoghq.eu'], redaction: ['email' => 'drop'])->stream;

    app(StreamDispatcher::class)->dispatch(EventFactory::make(context: ['email' => 'jane@acme.example']), [$stream]);
    $this->pumpStream($stream->id);

    expect(StreamDelivery::query()->where('status', DeliveryStatus::Delivered->value)->count())->toBe(1);
    Http::assertSent(function (Request $request): bool {
        $body = (string) gzdecode($request->body());

        return str_contains($body, 'evt_1') && ! str_contains($body, 'jane@acme.example');
    });
});

it('opens the circuit at once on refused credentials, keeps the events pending, and flags the stream', function (): void {
    FakeHttpTransport::refusingCredentials(403);
    $stream = datadogStream();

    app(StreamDispatcher::class)->dispatch(EventFactory::make(), [$stream]);
    $this->pumpStream($stream->id);

    $stream = LogStream::query()->findOrFail($stream->id);
    $row = StreamDelivery::query()->firstOrFail();

    // One 403 is enough — the threshold (5) is for transient failures only.
    expect($stream->circuit_opened_at)->not->toBeNull()
        ->and($stream->last_failure_kind)->toBe(FailureKind::Authentication)
        ->and($stream->health())->toBe(StreamHealth::ActionRequired)
        ->and($stream->last_error)->toContain('HTTP 403')
        ->and($stream->last_error)->not->toContain('dd-api-key-0123456789')
        // The event is kept, without spending its retry budget.
        ->and($row->status)->toBe(DeliveryStatus::Pending)
        ->and($row->attempts)->toBe(0);

    // While open, nothing more is sent — no hammering a 403.
    $row->update(['next_attempt_at' => null]);
    $this->pumpStream($stream->id);
    Http::assertSentCount(1);
});

it('probes once per cooldown while refused, then resumes as soon as the key is fixed', function (): void {
    $stream = datadogStream();
    app(StreamDispatcher::class)->dispatch(EventFactory::make(), [$stream]);

    // Datadog accepts only the rotated key.
    Http::fake(fn (Request $request) => Http::response('', $request->header('DD-API-KEY')[0] === 'dd-api-key-rotated-9876' ? 202 : 401));

    $this->pumpStream($stream->id);
    expect(LogStream::query()->findOrFail($stream->id)->health())->toBe(StreamHealth::ActionRequired);

    // After the cooldown, ONE probe — still refused, the circuit re-opens.
    Carbon::setTestNow(Carbon::now()->addSeconds(301));
    $this->pumpStream($stream->id);
    $this->pumpStream($stream->id);
    Http::assertSentCount(2);

    // The operator rotates the key: the breaker resets and the very next pump
    // delivers — no waiting out the cooldown.
    app(LogStreams::class)->update($stream->id, ['secret' => 'dd-api-key-rotated-9876']);
    $this->pumpStream($stream->id);

    $stream = LogStream::query()->findOrFail($stream->id);
    expect($stream->health())->toBe(StreamHealth::Healthy)
        ->and(StreamDelivery::query()->firstOrFail()->status)->toBe(DeliveryStatus::Delivered);
    Http::assertSent(fn (Request $request): bool => $request->header('DD-API-KEY')[0] === 'dd-api-key-rotated-9876');
});

it('keeps transient failures on the bounded retry path (degraded, not action required)', function (): void {
    FakeHttpTransport::rejecting(503);
    $stream = datadogStream();

    app(StreamDispatcher::class)->dispatch(EventFactory::make(), [$stream]);
    $this->pumpStream($stream->id);

    $stream = LogStream::query()->findOrFail($stream->id);
    expect($stream->health())->toBe(StreamHealth::Degraded)
        ->and($stream->last_failure_kind)->toBe(FailureKind::Transient)
        ->and($stream->circuit_opened_at)->toBeNull()
        ->and(StreamDelivery::query()->firstOrFail()->attempts)->toBe(1);
});

it('clamps batches to Datadog\'s 1000-entry limit whatever siem.batch says', function (): void {
    config(['siem.batch.max_records' => 5000, 'siem.batch.max_bytes' => 50 * 1024 * 1024, 'siem.batch.max_age' => 3600]);
    $sink = $this->fakeStreamSink();
    $stream = $this->createLogStream('dd', Destination::Datadog, '', secret: 'k', options: [])->stream;

    foreach (range(1, 1200) as $i) {
        app(StreamDispatcher::class)->dispatch(EventFactory::make(id: 'evt_'.$i), [$stream]);
    }

    $this->pumpStream($stream->id);

    expect(array_map(static fn (array $batch): int => count($batch['records']), $sink->batches()))->toBe([1000, 200]);
});

it('hands the sink the typed options and the secret through the target', function (): void {
    $sink = $this->fakeStreamSink();
    $stream = $this->createLogStream('s3', Destination::S3, '', secret: 'aws-secret', options: [
        'bucket' => 'audit', 'region' => 'eu-west-1', 'access_key_id' => 'AKIAEXAMPLE1234', 'gzip' => false,
    ])->stream;

    app(StreamDispatcher::class)->dispatch(EventFactory::make(), [$stream]);
    $this->pumpStream($stream->id);

    expect($sink->batches()[0]['target']->options)->toMatchArray([
        'destination' => 's3', 'bucket' => 'audit', 'region' => 'eu-west-1',
        'access_key_id' => 'AKIAEXAMPLE1234', 'secret' => 'aws-secret', 'gzip' => false,
    ]);
});

it('sends a marked test event and reports success', function (): void {
    FakeHttpTransport::accepting();
    $stream = datadogStream();

    $result = $this->testLogStream($stream->id);

    expect($result->delivered)->toBeTrue()->and($result->eventId)->toStartWith('siem-test-');
    Http::assertSent(fn (Request $request): bool => str_contains((string) gzdecode($request->body()), SinkStreamTester::ACTION));
    // A test bypasses the outbox.
    expect(StreamDelivery::query()->count())->toBe(0);
});

it('reports a refused test delivery with its kind, and leaves the stream untouched', function (): void {
    FakeHttpTransport::refusingCredentials(403);
    $stream = datadogStream();

    $result = $this->testLogStream($stream->id);

    expect($result->delivered)->toBeFalse()
        ->and($result->failure)->toBe(FailureKind::Authentication)
        ->and($result->error)->not->toContain('dd-api-key-0123456789')
        ->and(LogStream::query()->findOrFail($stream->id)->consecutive_failures)->toBe(0);
});

it('heals a flagged stream when a test delivery succeeds', function (): void {
    $sink = $this->fakeStreamSink()->refuseFor('dd');
    $stream = datadogStream();
    app(StreamDispatcher::class)->dispatch(EventFactory::make(), [$stream]);
    $this->pumpStream($stream->id);
    expect(LogStream::query()->findOrFail($stream->id)->health())->toBe(StreamHealth::ActionRequired);

    $sink->acceptAgain('dd');
    expect($this->testLogStream($stream->id)->delivered)->toBeTrue();

    $stream = LogStream::query()->findOrFail($stream->id);
    expect($stream->health())->toBe(StreamHealth::Healthy)->and($stream->circuit_opened_at)->toBeNull();
});
