<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Sinks;

use Cbox\Siem\ValueObjects\StreamTarget;

/**
 * Reads one transport hint from a {@see StreamTarget}'s flat option bag as a
 * string (booleans as `'1'`/`'0'`), or null when absent.
 */
final class SinkOptions
{
    public static function string(StreamTarget $target, string $key): ?string
    {
        $value = $target->options[$key] ?? null;

        if ($value === null) {
            return null;
        }

        if (is_bool($value)) {
            return $value ? '1' : '0';
        }

        return (string) $value;
    }
}
