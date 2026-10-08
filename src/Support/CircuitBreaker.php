<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Cbox\LaravelSiem\Enums\FailureKind;
use Cbox\LaravelSiem\Enums\StreamHealth;
use Cbox\LaravelSiem\Models\LogStream;
use Illuminate\Support\Carbon;

/**
 * A per-stream circuit breaker built on the stream's health columns. After
 * `failure_threshold` consecutive failures the breaker OPENS (stamping
 * `circuit_opened_at`) and delivery pauses for `cooldown_seconds`. Once the
 * cooldown elapses a single probe is allowed (half-open); a success closes the
 * breaker and resets the failure count, a failure re-opens it.
 *
 * A failure the destination will never accept as-is — refused credentials, a
 * missing bucket ({@see FailureKind::needsOperator()}) — {@see self::trip()}s the
 * breaker at once instead of waiting for the threshold: hammering a 401 is
 * pointless, so the stream probes once per cooldown until an operator fixes it.
 *
 * The breaker isolates a faulty destination — the app, the caller, and every
 * other stream keep working — but it never black-holes: failures are always
 * counted and the open/closed state and last error are visible on the model
 * ({@see self::health()}). Mutations are staged on the model; the caller persists.
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
        $stream->last_error = null;
        $stream->last_failure_kind = null;
    }

    public function recordFailure(LogStream $stream, FailureKind $kind = FailureKind::Transient, ?string $error = null): void
    {
        $stream->consecutive_failures = $stream->consecutive_failures + 1;
        $this->note($stream, $kind, $error);

        if ($kind->needsOperator() || $stream->consecutive_failures >= $this->threshold()) {
            $stream->circuit_opened_at = Carbon::now();
        }
    }

    /**
     * Open the breaker immediately (a refusal no retry can fix).
     */
    public function trip(LogStream $stream, FailureKind $kind, ?string $error = null): void
    {
        $this->recordFailure($stream, $kind->needsOperator() ? $kind : FailureKind::Authentication, $error);
    }

    /**
     * Forget all failure state — after an operator changed the stream's
     * credentials or settings, so the next pump tries straight away.
     */
    public function reset(LogStream $stream): void
    {
        $stream->consecutive_failures = 0;
        $stream->circuit_opened_at = null;
        $stream->last_error = null;
        $stream->last_failure_kind = null;
    }

    /**
     * The stream's status for a host to surface.
     */
    public function health(LogStream $stream): StreamHealth
    {
        if ($stream->consecutive_failures > 0 && $stream->last_failure_kind?->needsOperator() === true) {
            return StreamHealth::ActionRequired;
        }

        if ($this->isOpen($stream)) {
            return StreamHealth::Paused;
        }

        return $stream->consecutive_failures > 0 ? StreamHealth::Degraded : StreamHealth::Healthy;
    }

    /**
     * The cooldown in seconds (how long an open breaker pauses delivery).
     */
    public function cooldown(): int
    {
        return max(1, Config::int('siem.circuit_breaker.cooldown_seconds', 300));
    }

    private function note(LogStream $stream, FailureKind $kind, ?string $error): void
    {
        $stream->last_failure_kind = $kind;
        $stream->last_failure_at = Carbon::now();

        if ($error !== null) {
            $stream->last_error = mb_substr($error, 0, 2000);
        }
    }

    private function threshold(): int
    {
        return max(1, Config::int('siem.circuit_breaker.failure_threshold', 5));
    }
}
