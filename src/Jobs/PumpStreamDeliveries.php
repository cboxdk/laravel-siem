<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Jobs;

use Cbox\LaravelSiem\Enums\DeliveryStatus;
use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\Models\StreamDelivery;
use Cbox\LaravelSiem\Support\CircuitBreaker;
use Cbox\LaravelSiem\Support\Config;
use Cbox\LaravelSiem\Support\DeliveryBatcher;
use Cbox\LaravelSiem\Support\FormatterFactory;
use Cbox\LaravelSiem\Support\ModelClass;
use Cbox\LaravelSiem\Support\Redactor;
use Cbox\LaravelSiem\Support\SecretScrubber;
use Cbox\LaravelSiem\Support\SiemEventSerializer;
use Cbox\Siem\Contracts\StreamFormatter;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\ValueObjects\StreamTarget;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Carbon;
use Throwable;

/**
 * Drains one stream's outbox and ships it — off the request thread, on the queue.
 *
 * A run: skip if the stream is disabled or its circuit breaker is open; claim the
 * due `pending` rows; cut them into triple-bounded batches; for each batch redact
 * every event, format it with the destination's core formatter, and hand the
 * records to the {@see StreamSink}. On success the rows are marked delivered and
 * the breaker closes; on failure the rows get bounded exponential backoff with
 * jitter (or are dead-lettered past the cap), the breaker counts the failure
 * (opening past its threshold), and the run stops — a failing destination never
 * spins a retry loop and never blocks another stream.
 *
 * The job is {@see ShouldBeUnique} keyed by the stream: at most one pump per stream
 * runs at a time. Without this, a slow destination lets the next scheduled run start
 * while the previous is still mid-send and RE-CLAIM the same still-`pending` rows
 * (claim() does not lock or lease them), shipping every event to the customer's SIEM
 * two-plus times over — a self-amplifying duplicate storm, not the mild redelivery
 * that at-least-once permits. Uniqueness collapses that back to at-least-once.
 */
class PumpStreamDeliveries implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    /**
     * The unique lock's max lifetime — a ceiling on how long one pump may hold the
     * per-stream slot before another may run, so a crashed/stuck worker cannot wedge
     * a stream forever. Comfortably longer than a full drain of `batch.fetch_limit`
     * rows at the HTTP timeout.
     */
    public int $uniqueFor = 900;

    public function __construct(public readonly string $streamId) {}

    /**
     * One pump per stream at a time — the lock key. Concurrent dispatches for the
     * same stream (the per-minute scheduler while a previous run is still draining)
     * are dropped rather than doubling up on the same outbox rows.
     */
    public function uniqueId(): string
    {
        return $this->streamId;
    }

    public function handle(
        StreamSink $sink,
        CircuitBreaker $breaker,
        Redactor $redactor,
        FormatterFactory $formatters,
        DeliveryBatcher $batcher,
        SiemEventSerializer $serializer,
        SecretScrubber $scrubber,
    ): void {
        $stream = $this->stream();

        if ($stream === null || ! $stream->enabled) {
            return;
        }

        // Per-stream circuit breaker: while open (and inside cooldown), do not
        // deliver. Isolation — this returns without touching any other stream.
        if (! $breaker->shouldAttempt($stream)) {
            return;
        }

        $rows = $this->claim($stream);

        if ($rows === []) {
            return;
        }

        $formatter = $formatters->for($stream->destination);
        $batches = $batcher->batch(
            $rows,
            Config::int('siem.batch.max_records', 500),
            Config::int('siem.batch.max_bytes', 512 * 1024),
            Config::int('siem.batch.max_age', 5),
        );

        foreach ($batches as $batch) {
            try {
                $sink->send($this->records($batch, $stream, $redactor, $formatter, $serializer), $this->target($stream, $formatter));
            } catch (Throwable $e) {
                $this->recordFailure($stream, $batch, $breaker, $scrubber, $e);

                // Stop after the first failing batch: the destination is down, so
                // let the breaker/backoff govern the next run rather than hammering.
                // NB: no success is recorded, so the failure the breaker just counted
                // persists and accumulates across runs — a destination that fails a
                // later batch every run still trips the breaker.
                return;
            }

            $this->markDelivered($batch);
        }

        // Only a fully clean run (every batch delivered) resets the breaker. Doing
        // this per batch would let a single early success zero a failure count built
        // up across prior runs, so a partially-failing destination would never open
        // the breaker and would be hammered forever.
        $breaker->recordSuccess($stream);
        $stream->save();
    }

    /**
     * @param  list<StreamDelivery>  $batch
     * @return list<string>
     */
    private function records(array $batch, LogStream $stream, Redactor $redactor, StreamFormatter $formatter, SiemEventSerializer $serializer): array
    {
        $policy = $stream->redactionPolicy();
        $records = [];

        foreach ($batch as $row) {
            $event = $serializer->fromArray($row->payload);
            $event = $redactor->redact($event, $policy);
            $records[] = $formatter->format($event);
        }

        return $records;
    }

    private function target(LogStream $stream, StreamFormatter $formatter): StreamTarget
    {
        return new StreamTarget(
            name: $stream->name,
            endpoint: $stream->endpoint_url,
            options: [
                'destination' => $stream->destination->value,
                'auth' => $stream->auth->value,
                // Decrypted in memory only, for the sink to build the auth header.
                'secret' => $stream->secret,
                'content_type' => $formatter->contentType(),
                'gzip' => config('siem.http.gzip', false) === true,
            ],
        );
    }

    /**
     * @param  list<StreamDelivery>  $batch
     */
    private function markDelivered(array $batch): void
    {
        $now = Carbon::now();

        foreach ($batch as $row) {
            $row->status = DeliveryStatus::Delivered;
            $row->delivered_at = $now;
            $row->save();
        }
    }

    /**
     * @param  list<StreamDelivery>  $batch
     */
    private function recordFailure(LogStream $stream, array $batch, CircuitBreaker $breaker, SecretScrubber $scrubber, Throwable $e): void
    {
        $maxAttempts = max(1, Config::int('siem.retry.max_attempts', 12));
        $error = $scrubber->scrub($e->getMessage(), $stream->secret);

        foreach ($batch as $row) {
            $row->attempts = $row->attempts + 1;
            $row->last_error = $error;

            if ($row->attempts >= $maxAttempts) {
                // Bounded: past the cap, dead-letter and never retry again.
                $row->status = DeliveryStatus::Dead;
                $row->next_attempt_at = null;
            } else {
                $row->status = DeliveryStatus::Pending;
                $row->next_attempt_at = Carbon::now()->addSeconds($this->retryDelaySeconds($row->attempts));
            }

            $row->save();
        }

        $breaker->recordFailure($stream);
        $stream->save();
    }

    /**
     * Bounded exponential backoff with jitter, in seconds. The jitter is kept
     * below the per-step growth so successive delays are always longer.
     */
    private function retryDelaySeconds(int $attempts): int
    {
        $base = max(1, Config::int('siem.retry.base_seconds', 5));
        $max = max($base, Config::int('siem.retry.max_seconds', 3600));

        $exponent = min(30, max(0, $attempts - 1));
        $delay = min($max, $base * (2 ** $exponent));
        $jitter = random_int(0, $base - 1);

        return (int) $delay + $jitter;
    }

    /**
     * Claim the stream's due pending rows. Ordered oldest-first so backpressure and
     * batching see events in the order they were recorded.
     *
     * @return list<StreamDelivery>
     */
    private function claim(LogStream $stream): array
    {
        $class = $this->deliveryClass();

        return array_values($class::query()
            ->where('stream_id', $stream->id)
            ->where('status', DeliveryStatus::Pending->value)
            ->where(fn ($query) => $query->whereNull('next_attempt_at')->orWhere('next_attempt_at', '<=', Carbon::now()))
            ->orderBy('created_at')
            ->orderBy('id')
            ->limit(max(1, Config::int('siem.batch.fetch_limit', 5000)))
            ->get()
            ->all());
    }

    private function stream(): ?LogStream
    {
        return $this->streamClass()::query()->find($this->streamId);
    }

    /**
     * @return class-string<LogStream>
     */
    private function streamClass(): string
    {
        return ModelClass::resolve('siem.models.log_stream', LogStream::class);
    }

    /**
     * @return class-string<StreamDelivery>
     */
    private function deliveryClass(): string
    {
        return ModelClass::resolve('siem.models.stream_delivery', StreamDelivery::class);
    }
}
