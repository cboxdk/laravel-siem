---
title: Requirements
weight: 3
description: The PHP, Laravel, and dependency versions this package requires, taken from composer.json.
---

# Requirements

These are exactly what the Composer resolver enforces (`composer.json`) — nothing
invented.

## Runtime

- **PHP** `^8.4` (developed and CI-tested on 8.4 and 8.5).
- **Laravel** `^12.0 || ^13.0` — the current and previous major, via the
  `illuminate/*` components:
  - `illuminate/bus`, `illuminate/contracts`, `illuminate/database`,
    `illuminate/http`, `illuminate/queue`, `illuminate/support`.
- **[`cboxdk/siem`](https://github.com/cboxdk/siem)** `^0.1` — the framework-agnostic
  event model and formatters this layer delivers.
- **[`cboxdk/laravel-ssrf`](https://github.com/cboxdk/laravel-ssrf)** `^1.0` — the
  shared, independently-tested SSRF guard used for all HTTP egress.

No other third-party runtime dependencies.

## Infrastructure

- A **queue** connection for the pump (any Laravel driver: redis, database, sqs).
  Delivery never runs on the request thread.
- An **`APP_KEY`** — destination secrets use Laravel's `encrypted` cast.
- A **database** for the `log_streams` and `stream_deliveries` tables.

## Development

- `larastan/larastan` `^3.0` (PHPStan level max), `laravel/pint` `^1.18`,
  `orchestra/testbench` `^10.0 || ^11.0`, `pestphp/pest` `^3.5 || ^4.0`,
  `pestphp/pest-plugin-laravel`.
