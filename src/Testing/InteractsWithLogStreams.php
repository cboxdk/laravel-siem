<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Testing;

use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Enums\AuthScheme;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Jobs\PumpStreamDeliveries;
use Cbox\LaravelSiem\ValueObjects\RegisteredStream;
use Cbox\Siem\Contracts\StreamSink;

/**
 * Drop this into a host application's `TestCase` to drive the SIEM delivery engine
 * with zero network I/O: register streams through the real registry, swap the sink
 * for an in-memory {@see FakeStreamSink}, and run the pump synchronously.
 *
 *     $sink = $this->fakeStreamSink();
 *     $stream = $this->createLogStream('splunk', Destination::SplunkHec, 'https://hec.example.com', secret: 't');
 *     app(StreamDispatcher::class)->dispatch($event, [$stream->stream]);
 *     $this->pumpStream($stream->stream->id);
 *     $sink->assertSentTo('splunk');
 */
trait InteractsWithLogStreams
{
    protected ?FakeStreamSink $fakeStreamSink = null;

    /**
     * Bind an in-memory {@see FakeStreamSink} as the {@see StreamSink} contract so
     * the pump delivers into memory instead of over HTTP.
     */
    protected function fakeStreamSink(): FakeStreamSink
    {
        $fake = $this->fakeStreamSink ??= new FakeStreamSink;

        app()->instance(StreamSink::class, $fake);

        return $fake;
    }

    /**
     * @param  array<string, string>  $redaction
     * @param  array<string, mixed>  $filters
     */
    protected function createLogStream(
        string $name,
        Destination $destination,
        string $endpointUrl,
        ?string $secret = null,
        ?AuthScheme $auth = null,
        ?string $ownerKey = null,
        array $filters = [],
        array $redaction = [],
    ): RegisteredStream {
        return app(LogStreams::class)->create(
            $name,
            $destination,
            $endpointUrl,
            $secret,
            $auth,
            $ownerKey,
            $filters,
            $redaction,
        );
    }

    /**
     * Run one pump cycle for a stream synchronously (no queue worker needed).
     */
    protected function pumpStream(string $streamId): void
    {
        PumpStreamDeliveries::dispatchSync($streamId);
    }
}
