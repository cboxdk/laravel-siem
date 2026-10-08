---
title: Custom sink
weight: 1
description: Replace the HTTP sink with your own StreamSink implementation, and use the in-memory FakeStreamSink in tests.
---

# Custom sink

The pump depends on the core `Cbox\Siem\Contracts\StreamSink` contract, resolved
from the container. The default binding is `DestinationRouter`, which hands each batch
to `HttpStreamSink`, `DatadogStreamSink`, `S3StreamSink` or `GcsStreamSink` by
destination — each resolved from the container, so you can rebind one of them alone.
Rebind the contract itself to deliver over any transport (a message bus, a file, a
different HTTP client):

```php
use Cbox\Siem\Contracts\StreamSink;

$this->app->singleton(StreamSink::class, MyKafkaSink::class);
```

Your sink receives the already-formatted records and the `StreamTarget` (its
`options` bag carries `destination`, `auth`, `secret`, `content_type`, and `gzip`,
plus a cloud destination's own options such as `bucket` and `region`).
It must throw on failure so the pump can drive retry, dead-letter, and the circuit
breaker. Throw `DestinationRefused` (with a `FailureKind`) when the destination
refused the credentials or configuration — the pump then opens the circuit at once
instead of retrying (see [stream health](../core-concepts/stream-health.md)):

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

`refuseFor('name')` makes a target refuse like a destination rejecting credentials,
and `acceptAgain('name')` lifts it. For the real sinks,
`Cbox\LaravelSiem\Testing\FakeHttpTransport` programs Laravel's HTTP fake
(`accepting()`, `rejecting()`, `refusingCredentials()`, `unreachable()`) so you can
assert framing and auth with `Http::assertSent(...)`.

## Cloud credentials

Two more contracts are rebindable:

- `Contracts\AwsCredentialResolver` — supplies the credentials an S3 stream signs
  with. The default handles a static access key or an STS `AssumeRole` with the
  platform's identity. Bind an adapter over the AWS SDK's provider chain for
  instance-profile or web-identity credentials on a single-tenant install; never
  resolve a multi-tenant customer's stream to the platform's ambient role.
- `Contracts\GcsAccessTokens` — exchanges a service-account key for an access
  token. The default is the JWT-bearer grant with an encrypted cache.
