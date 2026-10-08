<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Sinks;

use Cbox\LaravelSiem\Enums\Destination;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\ValueObjects\StreamTarget;
use Illuminate\Contracts\Container\Container;

/**
 * The bound {@see StreamSink}: hands each batch to the sink for its destination —
 * {@see DatadogStreamSink}, {@see S3StreamSink}, {@see GcsStreamSink}, or the
 * {@see HttpStreamSink} for the HTTP collectors. Each sink is resolved from the
 * container, so a host can rebind any ONE of them (or this whole contract) without
 * touching the others.
 */
class DestinationRouter implements StreamSink
{
    public function __construct(private readonly Container $container) {}

    public function send(iterable $formattedRecords, StreamTarget $target): void
    {
        $this->sinkFor($this->destination($target))->send($formattedRecords, $target);
    }

    public function sinkFor(Destination $destination): StreamSink
    {
        $class = match ($destination) {
            Destination::Datadog => DatadogStreamSink::class,
            Destination::S3 => S3StreamSink::class,
            Destination::Gcs => GcsStreamSink::class,
            default => HttpStreamSink::class,
        };

        return $this->container->make($class);
    }

    private function destination(StreamTarget $target): Destination
    {
        return Destination::tryFrom(SinkOptions::string($target, 'destination') ?? '') ?? Destination::GenericJson;
    }
}
