<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Contracts;

use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\ValueObjects\TestDeliveryResult;

/**
 * Sends one small, clearly-marked test event to a stream's destination right now
 * (synchronously, bypassing the outbox) and reports whether it was accepted —
 * the "send test event" button behind a stream's settings page.
 *
 * A successful test proves the credentials and settings work, so it also closes
 * the stream's circuit breaker and clears an `action_required` status: pending
 * events resume on the next pump instead of waiting out the cooldown. A failed
 * test changes nothing on the stream.
 */
interface StreamTester
{
    public function test(LogStream $stream): TestDeliveryResult;
}
