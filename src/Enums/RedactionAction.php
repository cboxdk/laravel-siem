<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Enums;

/**
 * What a stream's redaction policy does to a matched field before it is
 * formatted and shipped. A configured sensitive field is never streamed raw.
 *
 * - `Hash` — replace the value with a stable SHA-256 hex digest (correlatable
 *            across events without revealing the value).
 * - `Mask` — replace the value with a fixed mask token.
 * - `Drop` — remove the field entirely.
 */
enum RedactionAction: string
{
    case Hash = 'hash';
    case Mask = 'mask';
    case Drop = 'drop';
}
