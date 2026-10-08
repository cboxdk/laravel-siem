<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\ValueObjects;

use Cbox\LaravelSiem\Contracts\StreamTester;
use Cbox\LaravelSiem\Enums\FailureKind;

/**
 * The outcome of a {@see StreamTester} test delivery: whether the marker event was
 * accepted, and if not, why (`failure`) with a secret-scrubbed `error` a host can
 * show the operator. `new TestDeliveryResult` is a successful result.
 */
readonly class TestDeliveryResult
{
    public function __construct(
        public bool $delivered = true,
        public ?FailureKind $failure = null,
        public ?string $error = null,
        public ?string $eventId = null,
    ) {}

    public static function delivered(string $eventId): self
    {
        return new self(true, null, null, $eventId);
    }

    public static function failed(FailureKind $failure, string $error, ?string $eventId = null): self
    {
        return new self(false, $failure, $error, $eventId);
    }
}
