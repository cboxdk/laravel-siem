---
title: Delivery engine
weight: 1
description: The outbox → pump → sink pipeline, with triple-bounded batching, bounded exponential backoff, dead-lettering, a per-stream circuit breaker, and bounded backpressure.
---

# Delivery engine

Three stages, each isolated from the others.

## 1. Outbox — `StreamDispatcher`

`DatabaseStreamDispatcher::dispatch(SiemEvent, iterable<LogStream>)` writes one
`pending` row (`stream_deliveries`) per stream whose action filter admits the
event. It is a cheap insert with no network, meant to run **inside the caller's
transaction** so the intent-to-deliver commits atomically with the caller's own
write. The event is stored as a JSON-safe payload (lossless, microsecond
timestamp).

Deny-by-default applies twice: a disabled stream is skipped, and a stream's
`filters` (`{"allow":[…]}` / `{"deny":[…]}`) can reject an action before any row is
written.

## 2. Pump — `PumpStreamDeliveries` (queued, per stream)

The pump runs on the queue, never on the request thread (a synchronous network
write on the request path is the single most-regretted design in log shipping).
Each run, for one stream:

1. **Skips** if the stream is disabled or its circuit breaker is open.
2. **Claims** the due `pending` rows (oldest first).
3. **Batches** them with three simultaneous bounds — `max_records`, `max_bytes`,
   and `max_age` — so one HTTP request can never exceed a destination's record or
   size limit, nor hold events past the latency budget. Whichever bound trips first
   cuts the batch.
4. For each batch: **redacts** every event, **formats** it with the destination's
   core formatter, and hands the records to the **sink**.

### On success

Rows are marked `delivered`, the stream's `consecutive_failures` resets,
`last_success_at` is stamped, and the circuit breaker closes.

### On failure

The batch throws (`StreamDeliveryFailed`). Each row's `attempts` increments and its
`next_attempt_at` is set by **bounded exponential backoff with jitter**
(`base · 2^(n-1)`, capped at `max_seconds`). Past `max_attempts` the row is marked
`dead` — dead-lettered, retained for inspection, and **never retried again**. The
run then stops (the destination is down; the breaker and backoff govern the next
attempt rather than hammering). Retries are always bounded — never an unbounded
loop.

## Per-stream circuit breaker

After `failure_threshold` consecutive failures the stream's breaker **opens**
(`circuit_opened_at` is stamped) and delivery pauses for `cooldown_seconds`. Once
the cooldown elapses one probe is allowed (half-open); a success closes it, a
failure re-opens it. Health is visible on the stream — `consecutive_failures`,
`last_success_at`, `circuit_opened_at`.

A failing destination is isolated: it never blocks the app, the caller, or another
stream. But it is never black-holed — failures are counted and surfaced, not
silently dropped.

## Backpressure (bounded outbox)

The outbox is bounded per stream by `backpressure.max_pending`. When the bound is
reached the configured `policy` sheds rows — `drop_oldest` (default; keep the
freshest signal) or `reject_new` — by **dead-lettering** them (never a silent
drop), logging a warning, and firing `Cbox\LaravelSiem\Events\OutboxOverflowed` as
a metric hook.

## Tuning

Every bound is config (`config/siem.php`): `batch.*`, `retry.*`,
`circuit_breaker.*`, `backpressure.*`, `http.*`. Defaults are production-sane.
