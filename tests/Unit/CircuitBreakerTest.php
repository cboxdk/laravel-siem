<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\Support\CircuitBreaker;
use Illuminate\Support\Carbon;

beforeEach(function (): void {
    config(['siem.circuit_breaker.failure_threshold' => 3]);
    config(['siem.circuit_breaker.cooldown_seconds' => 300]);
});

function freshStream(): LogStream
{
    $stream = new LogStream;
    $stream->consecutive_failures = 0;
    $stream->circuit_opened_at = null;

    return $stream;
}

it('opens only after the configured number of consecutive failures', function (): void {
    $breaker = new CircuitBreaker;
    $stream = freshStream();

    $breaker->recordFailure($stream);
    $breaker->recordFailure($stream);
    expect($stream->circuit_opened_at)->toBeNull()
        ->and($breaker->isOpen($stream))->toBeFalse();

    $breaker->recordFailure($stream);
    expect($stream->circuit_opened_at)->not->toBeNull()
        ->and($breaker->isOpen($stream))->toBeTrue();
});

it('allows a probe once the cooldown elapses and closes on success', function (): void {
    Carbon::setTestNow('2026-07-15 12:00:00');
    $breaker = new CircuitBreaker;
    $stream = freshStream();

    for ($i = 0; $i < 3; $i++) {
        $breaker->recordFailure($stream);
    }
    expect($breaker->shouldAttempt($stream))->toBeFalse();

    // After the cooldown a half-open probe is allowed.
    Carbon::setTestNow('2026-07-15 12:06:00');
    expect($breaker->shouldAttempt($stream))->toBeTrue();

    // A success closes the breaker and resets the failure count.
    $breaker->recordSuccess($stream);
    expect($stream->circuit_opened_at)->toBeNull()
        ->and($stream->consecutive_failures)->toBe(0)
        ->and($stream->last_success_at)->not->toBeNull();

    Carbon::setTestNow();
});
