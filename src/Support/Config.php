<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

/**
 * Type-safe reads of the package config. `config()` returns `mixed`; these helpers
 * narrow it to a concrete type (falling back to the default) so the delivery engine
 * never casts an unknown value blindly.
 */
class Config
{
    public static function int(string $key, int $default): int
    {
        $value = config($key, $default);

        if (is_int($value)) {
            return $value;
        }

        if (is_float($value) || (is_string($value) && is_numeric($value))) {
            return (int) $value;
        }

        return $default;
    }

    public static function bool(string $key, bool $default): bool
    {
        $value = config($key, $default);

        return is_bool($value) ? $value : $default;
    }

    public static function string(string $key, ?string $default = null): ?string
    {
        $value = config($key, $default);

        return is_string($value) ? $value : $default;
    }
}
