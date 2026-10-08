<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Cbox\LaravelSiem\Exceptions\InvalidStreamConfiguration;
use Cbox\Siem\ValueObjects\StreamTarget;

/**
 * Typed reads of a stream's `options` bag (a JSON column, or the flat scalar bag a
 * {@see StreamTarget} carries). Every reader validates as
 * it narrows, so a destination's typed options object is only ever built from
 * values it accepts. Messages name the field and never echo the value.
 */
final class OptionValues
{
    /**
     * A trimmed string, or null when absent/empty.
     *
     * @param  array<array-key, mixed>  $options
     */
    public static function string(array $options, string $key, ?string $pattern = null, string $hint = ''): ?string
    {
        $value = $options[$key] ?? null;

        if ($value === null) {
            return null;
        }

        if (! is_string($value) && ! is_int($value)) {
            throw InvalidStreamConfiguration::for($key, "The {$key} option must be a string.");
        }

        $value = trim((string) $value);

        if ($value === '') {
            return null;
        }

        if ($pattern !== null && preg_match($pattern, $value) !== 1) {
            throw InvalidStreamConfiguration::for($key, trim("The {$key} option is not valid. {$hint}"));
        }

        return $value;
    }

    /**
     * A required string — as {@see self::string()}, but absence is an error.
     *
     * @param  array<array-key, mixed>  $options
     */
    public static function required(array $options, string $key, ?string $pattern = null, string $hint = ''): string
    {
        return self::string($options, $key, $pattern, $hint)
            ?? throw InvalidStreamConfiguration::for($key, "The {$key} option is required.");
    }

    /**
     * A boolean, accepting the shapes a form or a JSON column produce.
     *
     * @param  array<array-key, mixed>  $options
     */
    public static function bool(array $options, string $key): ?bool
    {
        $value = $options[$key] ?? null;

        return match (true) {
            $value === null, $value === '' => null,
            is_bool($value) => $value,
            $value === 1, $value === '1', $value === 'true' => true,
            $value === 0, $value === '0', $value === 'false' => false,
            default => throw InvalidStreamConfiguration::for($key, "The {$key} option must be true or false."),
        };
    }

    /**
     * An object-key prefix: no leading/trailing slash, no empty or `.`/`..`
     * segments, and only characters that are safe in an S3/GCS object name
     * without encoding.
     *
     * @param  array<array-key, mixed>  $options
     */
    public static function prefix(array $options, string $key = 'prefix'): string
    {
        $prefix = self::string($options, $key);

        if ($prefix === null) {
            return '';
        }

        $prefix = trim($prefix, '/');

        if ($prefix === '') {
            return '';
        }

        if (strlen($prefix) > 512 || preg_match('#^[A-Za-z0-9!_.*\'()\-/=]+$#', $prefix) !== 1) {
            throw InvalidStreamConfiguration::for($key, 'The prefix may contain letters, digits, slashes and !_.*\'()-= only (at most 512 characters).');
        }

        foreach (explode('/', $prefix) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                throw InvalidStreamConfiguration::for($key, 'The prefix may not contain empty, "." or ".." segments.');
            }
        }

        return $prefix;
    }
}
