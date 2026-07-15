<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Events;

/**
 * Fired when a stream's outbox hits its `max_pending` bound and the backpressure
 * policy sheds rows (dead-letters them). This is the metric hook: listen for it to
 * alert or emit a gauge. The shed is also logged as a warning — backpressure is
 * always explicit and counted, never a silent black-hole.
 */
readonly class OutboxOverflowed
{
    public function __construct(
        public string $streamId,
        public ?string $ownerKey,
        public int $shed,
        public string $policy,
        public int $pending,
    ) {}
}
