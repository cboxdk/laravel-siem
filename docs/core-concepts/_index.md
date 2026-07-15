---
title: Core concepts
weight: 4
description: How the delivery engine works — the outbox, the queued pump, batching, retry, dead-letter, the circuit breaker, and the delivery semantics.
---

# Core concepts

The delivery engine turns "I emitted a security event" into "it reliably reached
the customer's SIEM" without ever blocking the request, losing an event on a
transient outage, or letting one bad destination take down the app.

- [Delivery engine](delivery-engine.md) — the outbox → pump → sink pipeline and
  every safeguard on it (batching bounds, retry/backoff, dead-letter, circuit
  breaker, backpressure).
- [Outbox and semantics](outbox-and-semantics.md) — what the transactional outbox
  guarantees, and the honest truth about ordering and duplicates (at-least-once,
  unordered, dedup by event id).
