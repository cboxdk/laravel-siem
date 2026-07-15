---
title: Custom sink
weight: 1
description: Replace the HTTP sink with your own StreamSink implementation, and use the in-memory FakeStreamSink in tests.
---

# Custom sink

The pump depends on the core `Cbox\Siem\Contracts\StreamSink` contract, resolved
from the container. The default binding is `HttpStreamSink`. Rebind it to deliver
over any transport (a message bus, a file, a different HTTP client):

```php
use Cbox\Siem\Contracts\StreamSink;

$this->app->singleton(StreamSink::class, MyKafkaSink::class);
```

Your sink receives the already-formatted records and the `StreamTarget` (its
`options` bag carries `destination`, `auth`, `secret`, `content_type`, and `gzip`).
It must throw on failure so the pump can drive retry, dead-letter, and the circuit
breaker:

```php
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\ValueObjects\StreamTarget;

class MyKafkaSink implements StreamSink
{
    public function send(iterable $formattedRecords, StreamTarget $target): void
    {
        // ... publish; on error:
        throw new StreamDeliveryFailed('kafka publish failed');
    }
}
```

## In tests: `FakeStreamSink`

`Cbox\LaravelSiem\Testing\FakeStreamSink` captures batches instead of shipping
them, and can be told to fail for chosen targets. Compose
`InteractsWithLogStreams` and call `fakeStreamSink()`:

```php
use Cbox\LaravelSiem\Testing\InteractsWithLogStreams;

$sink = $this->fakeStreamSink();               // bound as the StreamSink contract
$sink->failFor('down');                         // simulate a dead destination

$this->pumpStream($stream->id);

$sink->assertSentTo('healthy');
$sink->assertNoRecordContains('a-secret-value'); // prove redaction reached the sink
```

For the real `HttpStreamSink`, `Cbox\LaravelSiem\Testing\FakeHttpTransport` programs
Laravel's HTTP fake (`accepting()`, `rejecting()`, `unreachable()`) so you can assert
framing and auth with `Http::assertSent(...)`.
