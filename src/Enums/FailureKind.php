<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Enums;

/**
 * Why a delivery to a stream failed — what decides whether retrying can help.
 *
 * - `Transient`      — a network error, a timeout, a 429 or a 5xx. Retried with
 *                      bounded backoff; the circuit breaker opens after the
 *                      configured threshold.
 * - `Authentication` — the destination refused the credentials (401/403, a bad
 *                      signature, a revoked key, a token exchange the identity
 *                      provider refused). Retrying the same credentials cannot
 *                      succeed, so the circuit opens IMMEDIATELY and the events
 *                      wait (without spending their retry budget) until an
 *                      operator fixes the stream.
 * - `Configuration`  — the destination says the target does not exist or is in
 *                      the wrong place (no such bucket, wrong region, malformed
 *                      settings). Handled like `Authentication`.
 */
enum FailureKind: string
{
    case Transient = 'transient';
    case Authentication = 'authentication';
    case Configuration = 'configuration';

    /**
     * True when only an operator can fix it — retrying unchanged is pointless.
     */
    public function needsOperator(): bool
    {
        return $this !== self::Transient;
    }
}
