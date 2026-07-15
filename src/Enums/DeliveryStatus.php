<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Enums;

/**
 * The lifecycle of one outbox row.
 *
 * - `Pending`   — written (in the caller's transaction) and awaiting the pump.
 * - `Delivered` — accepted by the destination; terminal.
 * - `Dead`      — dead-lettered after the retry cap or by a backpressure policy;
 *                 retained for inspection and NEVER retried again. Terminal.
 */
enum DeliveryStatus: string
{
    case Pending = 'pending';
    case Delivered = 'delivered';
    case Dead = 'dead';
}
