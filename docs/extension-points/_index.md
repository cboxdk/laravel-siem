---
title: Extension points
weight: 6
description: Customize delivery through contracts and config — replace the sink, add a destination, or swap the registry.
---

# Extension points

Everything is a contract bound in the service provider, so a host overrides by
rebinding — no forking.

- [Custom sink](custom-sink.md) — replace `Cbox\Siem\Contracts\StreamSink` to
  deliver over a different transport (or to test in memory with `FakeStreamSink`).
- [Custom destination](custom-destination.md) — how destinations map to core
  formatters, and how to extend the models and registry.
