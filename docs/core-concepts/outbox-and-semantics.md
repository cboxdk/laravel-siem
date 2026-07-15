---
title: Outbox and semantics
weight: 2
description: What the transactional outbox guarantees — at-least-once delivery, unordered, with duplicates possible — and how to consume it idempotently.
---

# Outbox and delivery semantics

## The transactional outbox

`dispatch()` writes the outbox row on the caller's own database connection. Wrap it
in your transaction and the guarantee is simple:

- If your transaction **commits**, the `pending` row is durably there and *will* be
  delivered (retried until it succeeds or is dead-lettered).
- If your transaction **rolls back**, the row rolls back with it — no orphan
  delivery for an event that never really happened.

This is what makes delivery **at-least-once** rather than best-effort. A SIEM
outage cannot roll back your business write, and your business write cannot be
recorded without also recording the intent to stream it.

```php
DB::transaction(function () use ($event, $streams) {
    // business write ...
    app(StreamDispatcher::class)->dispatch($event, $streams);
});
```

## Be honest about the guarantees

Delivery is **at-least-once and unordered**. Do not assume exactly-once or ordered
delivery — the design deliberately does not promise them:

- **Duplicates are possible.** A batch can be delivered and then fail to be marked
  (worker crash, connection reset after the SIEM accepted it); the row stays
  `pending` and is retried. Two workers can also claim overlapping rows.
- **Order is not guaranteed.** Batches, retries, and multiple streams interleave.
- **The dedup key is the event id.** Each `SiemEvent` carries a stable `id`. Use it
  (not content equality) to deduplicate on the consuming side. Any downstream
  processing must be **idempotent**.

## What this package does not do

- It does not de-duplicate for you — the consumer (or the SIEM) must.
- It does not guarantee ordering or exactly-once — see above.
- It does not itself produce a hash-chained, tamper-evident audit trail; that is
  the job of the audit binding (in `cboxdk/laravel-id`) that writes into this
  outbox. This package is the transport, not the ledger.
