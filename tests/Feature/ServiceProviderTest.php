<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\LaravelSiem\DatabaseLogStreams;
use Cbox\LaravelSiem\DatabaseStreamDispatcher;
use Cbox\LaravelSiem\Sinks\HttpStreamSink;
use Cbox\Siem\Contracts\StreamSink;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

it('binds the package contracts to their default implementations', function (): void {
    expect(app(LogStreams::class))->toBeInstanceOf(DatabaseLogStreams::class)
        ->and(app(StreamDispatcher::class))->toBeInstanceOf(DatabaseStreamDispatcher::class)
        ->and(app(StreamSink::class))->toBeInstanceOf(HttpStreamSink::class);
});

it('merges the package config', function (): void {
    expect(config('siem.retry.max_attempts'))->toBe(12)
        ->and(config('siem.circuit_breaker.failure_threshold'))->toBe(5)
        ->and(config('siem.http.tls_verify'))->toBeTrue();
});

it('creates the outbox tables', function (): void {
    expect(Schema::hasTable('log_streams'))->toBeTrue()
        ->and(Schema::hasTable('stream_deliveries'))->toBeTrue();
});
