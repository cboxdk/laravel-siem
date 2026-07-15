<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Models\StreamDelivery;
use Cbox\LaravelSiem\Tests\Fixtures\EventFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['siem.http.verify_url' => false]);
    // Keep the breaker out of the way so retries can accrue past the cap here.
    config(['siem.circuit_breaker.failure_threshold' => 100]);
    Carbon::setTestNow('2026-07-15 12:00:00');
});

afterEach(fn () => Carbon::setTestNow());

it('retries a failing delivery with increasing backoff, then dead-letters at the cap', function (): void {
    config(['siem.retry.max_attempts' => 3]);

    $sink = $this->fakeStreamSink()->failFor('down');
    $registered = $this->createLogStream('down', Destination::GenericJson, 'https://down.example.test');

    app(StreamDispatcher::class)->dispatch(EventFactory::make(), [$registered->stream]);

    // Attempt 1 → still pending, a backoff window is scheduled.
    $this->pumpStream($registered->stream->id);
    $row = StreamDelivery::query()->firstOrFail();
    expect($row->status->value)->toBe('pending')->and($row->attempts)->toBe(1);
    $firstNext = $row->next_attempt_at;
    expect($firstNext)->not->toBeNull();

    // Make it due again; attempt 2 → later backoff window than attempt 1.
    $row->update(['next_attempt_at' => Carbon::now()->subMinute()]);
    $this->pumpStream($registered->stream->id);
    $row->refresh();
    expect($row->attempts)->toBe(2)
        ->and($row->next_attempt_at->greaterThan($firstNext))->toBeTrue();

    // Make it due again; attempt 3 hits the cap → dead-lettered, no retry window.
    $row->update(['next_attempt_at' => Carbon::now()->subMinute()]);
    $this->pumpStream($registered->stream->id);
    $row->refresh();
    expect($row->status->value)->toBe('dead')
        ->and($row->attempts)->toBe(3)
        ->and($row->next_attempt_at)->toBeNull();

    // A dead row is never claimed again.
    $this->pumpStream($registered->stream->id);
    $row->refresh();
    expect($row->attempts)->toBe(3);
});

it('does not put the secret into a stored delivery error', function (): void {
    $this->fakeStreamSink()->failFor('hec');
    $registered = $this->createLogStream('hec', Destination::SplunkHec, 'https://hec.example.test', secret: 'top-secret-hec-token');

    app(StreamDispatcher::class)->dispatch(EventFactory::make(), [$registered->stream]);
    $this->pumpStream($registered->stream->id);

    $row = StreamDelivery::query()->firstOrFail();
    expect($row->last_error)->not->toBeNull()
        ->and($row->last_error)->not->toContain('top-secret-hec-token');
});
