<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Contracts;

use Cbox\LaravelSiem\Models\LogStream;
use Cbox\Siem\ValueObjects\SiemEvent;

/**
 * Writes the transactional outbox. For each stream whose action filter admits the
 * event, {@see self::dispatch()} inserts one cheap `pending` row — nothing is sent
 * synchronously. Call it INSIDE the caller's own database transaction so the
 * business/audit write and the intent-to-deliver commit atomically; a rolled-back
 * caller leaves no orphan delivery. The queued pump does the shipping later.
 */
interface StreamDispatcher
{
    /**
     * Enqueue `$event` for every matching stream. Returns the number of outbox
     * rows written (0 when no stream matches — deny-by-default).
     *
     * @param  iterable<int, LogStream>  $streams
     */
    public function dispatch(SiemEvent $event, iterable $streams): int;
}
