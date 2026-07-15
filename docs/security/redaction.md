---
title: Redaction
weight: 2
description: Per-field PII redaction — hash, mask, or drop sensitive fields before an event is formatted, so a configured field is never streamed raw.
---

# Redaction

A stream carries a `redaction` policy: a per-field map applied to each event
**before** it is formatted, so the pure core formatter never sees the raw value and
a configured sensitive field is never streamed raw.

## Policy

The policy is keyed by field name, with one of three actions:

```php
app(LogStreams::class)->create(
    name: 'splunk',
    destination: Destination::SplunkHec,
    endpointUrl: 'https://hec.example.com',
    secret: 'token',
    redaction: [
        'password' => 'drop',   // remove the field entirely
        'email'    => 'hash',   // stable SHA-256 hex (correlatable, not reversible)
        'card'     => 'mask',   // replace with a fixed mask token
    ],
);
```

- **`hash`** — replaces the value with `sha256(value)` in hex. The same input
  always hashes to the same digest, so you can still correlate events by a field
  without revealing it.
- **`mask`** — replaces the value with a fixed token (`[REDACTED]`).
- **`drop`** — removes the field.

## What can be redacted

- Any key in the event's flattened `context` bag (`context.<key>`), matched by name.
- The top-level `message` and `source_ip` fields (match on `message` / `source_ip`).

Redaction is deny-by-default friendly: name the sensitive fields for a destination
and they are guaranteed never to reach it in the clear. This is proven in the test
suite — a hashed field's raw value never appears in any record handed to the sink.

## Coverage limit — the identity fields are not redactable

The policy targets `context.*`, `message`, and `source_ip` only. The event's
**`actor.id` and `target.id`** (emitted as CEF `suser`/`targetId`, GELF
`_actor_id`, ECS `user.id`, etc.) are structural identity fields and are **not**
run through the redactor — a SIEM needs a stable subject to correlate on. So do not
place free-form PII (a raw email, a full name, a token) in `actor.id`/`target.id`
expecting it to be redacted; put it in a named `context` field and add a policy for
it. Use a stable opaque identifier for the actor/target, and let the redactable
`context` carry anything that must be masked or dropped per destination.
