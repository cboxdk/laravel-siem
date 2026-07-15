---
title: Introduction
weight: 1
description: The SIEM log-streaming delivery engine for Laravel — a durable outbox, queued batched delivery with retry, dead-letter, and circuit breaker, SSRF-guarded egress, encrypted secrets, and PII redaction.
---

# Cbox SIEM for Laravel

Cbox SIEM for Laravel is the delivery engine that ships normalized security
events to real SIEMs — Splunk HEC, Elastic (ECS), Graylog (GELF), ArcSight/syslog
(CEF), or any HTTP JSON collector — durably and safely.

It is the **Laravel wrapper** over the framework-agnostic
[`cboxdk/siem`](https://github.com/cboxdk/siem) core. The two tiers split cleanly:

## The two-tier story

- **`cboxdk/siem` (core)** owns the *shape* of the data: the normalized
  `SiemEvent` value object and the pure, deterministic formatters that turn one
  event into the exact bytes each SIEM ingests. It is zero-dependency and does no
  I/O — it never dials a network or holds a secret.
- **`cboxdk/laravel-siem` (this package)** owns *delivery*: a transactional
  outbox, a queued pump that batches and ships, SSRF-guarded HTTP egress, encrypted
  destination secrets, per-field PII redaction, retry/backoff/dead-letter, and a
  per-stream circuit breaker.

A third tier consumes this one: an audit binding (in
[`cboxdk/laravel-id`](https://github.com/cboxdk/laravel-id)) writes an audit record
and an outbox row in the same transaction, so its audit trail streams to a
customer's SIEM at-least-once. That binding is **not** part of this package.

## Mental model

```
your app ──emit──▶ StreamDispatcher ──insert (in your txn)──▶ outbox (stream_deliveries)
                                                                    │
                                            queued PumpStreamDeliveries (per stream)
                                                                    │
                        redact ─▶ core formatter ─▶ HttpStreamSink ─▶ your SIEM
                                                     (SSRF-guarded, TLS-on, batched)
```

Delivery is **deny-by-default**: with no enabled `LogStream`, nothing is written
and nothing is sent. Delivery is **at-least-once and unordered** — see
[outbox and semantics](core-concepts/outbox-and-semantics.md).

## Sections

- [Quickstart](quickstart.md) — configure a stream and deliver in one read.
- [Requirements](requirements.md) — PHP, Laravel, and dependency versions.
- [Core concepts](core-concepts/_index.md) — the delivery engine and its semantics.
- [Cookbook](cookbook/_index.md) — stream to Splunk, stream to Elastic.
- [Extension points](extension-points/_index.md) — custom sinks and destinations.
- [Security](security/_index.md) — egress/SSRF, secrets, and redaction.

## Where things live

This package documents only its own delivery layer. The event model, the
formatters, and their escaping/threat model are documented in
[`cboxdk/siem`](https://github.com/cboxdk/siem).
