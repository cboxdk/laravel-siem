<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Cbox\LaravelSiem\Models\LogStream;
use Illuminate\Support\Carbon;

/**
 * A per-stream circuit breaker built on the stream's health columns. After
 * `failure_threshold` consecutive failures the breaker OPENS (stamping
 * `circuit_opened_at`) and delivery pauses for `cooldown_seconds`. Once the
 * cooldown elapses a single probe is allowed (half-open); a success closes the
 * breaker and resets the failure count, a failure re-opens it.
 *
 * The breaker isolates a faulty destination — the app, the caller, and every
 * other stream keep working — but it never black-holes: failures are always
 * counted and the open/closed state is visible on the model. Mutations are staged
 * on the model; the caller persists.
 */
class CircuitBreaker
{
    /**
     * True while the breaker is open and its cooldown has not yet elapsed — the
     * stream must not be delivered to right now.
     */
    public function isOpen(LogStream $stream): bool
    {
        if ($stream->circuit_opened_at === null) {
            return false;
        }

        return $stream->circuit_opened_at->copy()->addSeconds($this->cooldown())->isFuture();
    }

    /**
     * True when a delivery attempt is permitted: the breaker is closed, or it is
     * open but the cooldown has elapsed (a half-open probe).
     */
    public function shouldAttempt(LogStream $stream): bool
    {
        return ! $this->isOpen($stream);
    }

    public function recordSuccess(LogStream $stream): void
    {
        $stream->consecutive_failures = 0;
        $stream->last_success_at = Carbon::now();
        $stream->circuit_opened_at = null;
    }

    public function recordFailure(LogStream $stream): void
    {
        $stream->consecutive_failures = $stream->consecutive_failures + 1;

        if ($stream->consecutive_failures >= $this->threshold()) {
            $stream->circuit_opened_at = Carbon::now();
        }
    }

    private function threshold(): int
    {
        return max(1, Config::int('siem.circuit_breaker.failure_threshold', 5));
    }

    private function cooldown(): int
    {
        return max(1, Config::int('siem.circuit_breaker.cooldown_seconds', 300));
    }
}
