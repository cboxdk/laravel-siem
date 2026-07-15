<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Enums;

/**
 * How the HTTP sink authenticates a batch to its destination.
 *
 * - `None`   — no credential (an unauthenticated internal collector).
 * - `Bearer` — `Authorization: Bearer <secret>`.
 * - `Splunk` — `Authorization: Splunk <token>` (Splunk HEC).
 * - `Hmac`   — an HMAC-SHA256 signature over `timestamp.body`, sent in
 *              `X-Cbox-Timestamp` / `X-Cbox-Signature` (replay-resistant).
 */
enum AuthScheme: string
{
    case None = 'none';
    case Bearer = 'bearer';
    case Splunk = 'splunk';
    case Hmac = 'hmac';
}
