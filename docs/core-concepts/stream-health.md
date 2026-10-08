---
title: Stream health and test delivery
weight: 3
description: How refused credentials differ from transient failures, the stream status a host shows, and the synchronous test delivery.
---

# Stream health and test delivery

## Two kinds of failure

| Kind | Examples | What the pump does |
|------|----------|--------------------|
| `transient` | timeout, connection refused, 408, 429, 5xx | bounded exponential backoff per row, dead-letter at the cap; the breaker opens after `failure_threshold` consecutive failures |
| `authentication` / `configuration` | 401/403, a bad signature, a revoked key, a refused token exchange, no such bucket, wrong region | the breaker opens **at once**; the rows stay pending and their `attempts` are **not** incremented |

A sink signals the second kind by throwing
`Cbox\LaravelSiem\Exceptions\DestinationRefused` (a `StreamDeliveryFailed` subclass
carrying a `FailureKind`). Every built-in sink maps responses this way, including the
HTTP collectors (a 401/403 from Splunk or Elastic is a refusal too).

Why: retrying a refused key cannot succeed, and burning the retry budget would
dead-letter audit events because of a credential problem. Instead the stream probes
once per `circuit_breaker.cooldown_seconds` until it is fixed, and the outbox bound
(`backpressure.max_pending`) still caps how much can pile up.

## The status

Every failure records `last_error` (scrubbed), `last_failure_kind` and
`last_failure_at` on the stream; a success clears them. `$stream->health()` (or
`CircuitBreaker::health($stream)`) answers:

| Health | Meaning |
|--------|---------|
| `healthy` | the last attempt succeeded |
| `degraded` | transient failures, still retrying |
| `paused` | the breaker is open after repeated transient failures; resumes on its own |
| `action_required` | the destination refused the credentials or configuration; an operator must fix it |

Updating a stream's `secret`, `options`, `endpoint_url` or `destination` through
`LogStreams::update()` re-validates the settings and resets the breaker, so the next
pump delivers straight away.

## Test delivery

```php
use Cbox\LaravelSiem\Contracts\StreamTester;

$result = app(StreamTester::class)->test($stream);

$result->delivered;  // bool
$result->failure;    // FailureKind|null
$result->error;      // scrubbed message, for the operator
$result->eventId;    // the marker event's id (siem-test-…)
```

The tester formats one marker event (action `siem.stream.test`, a message saying it
is safe to ignore) with the stream's formatter and redaction and sends it through the
bound sink — same target, SSRF guard and credentials as the pump — synchronously and
outside the outbox. A success also closes the breaker and clears `action_required`;
a failure changes nothing on the stream.
