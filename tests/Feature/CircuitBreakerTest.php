<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Jobs\PumpStreamDeliveries;
use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\Models\StreamDelivery;
use Cbox\LaravelSiem\Tests\Fixtures\EventFactory;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['siem.http.verify_url' => false]);
    config(['siem.circuit_breaker.failure_threshold' => 1]);
});

it('opens the breaker after the failure threshold and isolates the fault from a healthy stream', function (): void {
    $sink = $this->fakeStreamSink()->failFor('broken');

    $broken = $this->createLogStream('broken', Destination::GenericJson, 'https://broken.example.test');
    $healthy = $this->createLogStream('healthy', Destination::GenericJson, 'https://healthy.example.test');

    app(StreamDispatcher::class)->dispatch(EventFactory::make(), [$broken->stream, $healthy->stream]);

    // The failing stream trips its breaker...
    $this->pumpStream($broken->stream->id);
    $brokenModel = LogStream::query()->findOrFail($broken->stream->id);
    expect($brokenModel->consecutive_failures)->toBe(1)
        ->and($brokenModel->circuit_opened_at)->not->toBeNull();

    // ...and the healthy stream delivers regardless (fault isolation — one failing
    // destination never stops another).
    $this->pumpStream($healthy->stream->id);
    $sink->assertSentTo('healthy');
    expect(StreamDelivery::query()->where('stream_id', $healthy->stream->id)->where('status', 'delivered')->count())->toBe(1);

    // While open, the broken stream is not delivered to again — but its failure is
    // counted and its state is visible (no silent black-hole).
    $this->pumpStream($broken->stream->id);
    expect(StreamDelivery::query()->where('stream_id', $broken->stream->id)->where('status', 'delivered')->count())->toBe(0);
});

it('opens the breaker for a destination that fails a LATER batch, not just a fully-down one', function (): void {
    // Regression: a mid-run success must not zero the failure count, or a
    // partially-failing destination (batch 1 accepted, batch 2 rejected each run)
    // would never trip the breaker and would be hammered forever.
    config(['siem.circuit_breaker.failure_threshold' => 2]);
    config(['siem.batch.max_records' => 1]); // one row per batch → two batches

    // The destination accepts the first batch of the run, then fails the second.
    $sink = $this->fakeStreamSink()->failAfter(1);

    $stream = $this->createLogStream('partial', Destination::GenericJson, 'https://partial.example.test');

    // Simulate one prior failed run already on the clock (threshold is 2).
    $model = LogStream::query()->findOrFail($stream->stream->id);
    $model->consecutive_failures = 1;
    $model->save();

    // Two pending rows → the pump cuts two batches: #1 delivers, #2 fails.
    app(StreamDispatcher::class)->dispatch(EventFactory::make(id: 'evt_a'), [$stream->stream]);
    app(StreamDispatcher::class)->dispatch(EventFactory::make(id: 'evt_b'), [$stream->stream]);

    $this->pumpStream($stream->stream->id);

    // The batch-1 success did NOT reset the count; batch-2's failure took it to the
    // threshold and opened the breaker. (Under the per-batch-reset bug this stayed 1
    // and never opened.)
    $reloaded = LogStream::query()->findOrFail($stream->stream->id);
    expect($reloaded->consecutive_failures)->toBe(2)
        ->and($reloaded->circuit_opened_at)->not->toBeNull();

    // Batch 1 really did deliver (the success was genuine, just not breaker-resetting).
    expect(StreamDelivery::query()->where('stream_id', $stream->stream->id)->where('status', 'delivered')->count())->toBe(1);
});

it('runs at most one pump per stream (unique by stream id) so a slow sink cannot re-claim rows', function (): void {
    // Regression for the duplicate-amplification defect: without per-stream
    // uniqueness, an overlapping scheduled run re-claims still-pending rows and
    // multiplies delivery to the customer's endpoint.
    $job = new PumpStreamDeliveries('stream_xyz');

    expect($job)->toBeInstanceOf(ShouldBeUnique::class)
        ->and($job->uniqueId())->toBe('stream_xyz')
        ->and($job->uniqueFor)->toBeGreaterThan(0);
});
