<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Enums;

/**
 * A stream's delivery health, derived from its circuit-breaker columns — the
 * status a host surfaces next to each stream.
 *
 * - `Healthy`        — the last attempt succeeded (or none failed yet).
 * - `Degraded`       — recent transient failures, still retrying, breaker closed.
 * - `Paused`         — the breaker is open after repeated transient failures;
 *                      delivery resumes on its own after the cooldown.
 * - `ActionRequired` — the destination refused the credentials or the
 *                      configuration. It will not heal on its own: fix the stream
 *                      (rotating the secret or changing the options resets it) or
 *                      run a successful test delivery.
 */
enum StreamHealth: string
{
    case Healthy = 'healthy';
    case Degraded = 'degraded';
    case Paused = 'paused';
    case ActionRequired = 'action_required';
}
