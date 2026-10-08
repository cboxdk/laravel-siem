<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Exceptions;

use Cbox\LaravelSiem\Enums\FailureKind;
use Throwable;

/**
 * The destination refused the stream's credentials or configuration — a failure
 * retrying cannot fix (HTTP 401/403, an invalid signature, no such bucket, a
 * refused token exchange). The pump opens the stream's circuit immediately,
 * records the {@see FailureKind} as the stream's status, and keeps the events
 * pending without spending their retry budget, so they flush once an operator
 * fixes the stream. The message is already scrubbed of any secret.
 */
class DestinationRefused extends StreamDeliveryFailed
{
    public function __construct(
        string $message,
        public readonly FailureKind $kind = FailureKind::Authentication,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, previous: $previous);
    }

    public static function authentication(string $message, ?Throwable $previous = null): self
    {
        return new self($message, FailureKind::Authentication, $previous);
    }

    public static function configuration(string $message, ?Throwable $previous = null): self
    {
        return new self($message, FailureKind::Configuration, $previous);
    }
}
