<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Contracts;

use Cbox\LaravelSiem\Enums\AuthScheme;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\ValueObjects\RegisteredStream;

/**
 * The registry of configured SIEM destinations. Delivery is deny-by-default: with
 * no enabled stream, {@see self::enabled()} returns nothing and the dispatcher
 * writes nothing — the package never invents a destination.
 */
interface LogStreams
{
    /**
     * Register a stream. When `$secret` is null and the auth scheme needs one, a
     * signing key is generated; the effective plaintext secret is revealed once on
     * the returned {@see RegisteredStream} and only ciphertext is persisted. The
     * endpoint URL is SSRF-checked before it is stored.
     *
     * @param  array<string, string>  $redaction  per-field policy (field => hash|mask|drop)
     * @param  array<string, mixed>  $filters  action allow/deny policy
     */
    public function create(
        string $name,
        Destination $destination,
        string $endpointUrl,
        ?string $secret = null,
        ?AuthScheme $auth = null,
        ?string $ownerKey = null,
        array $filters = [],
        array $redaction = [],
    ): RegisteredStream;

    /**
     * Update mutable attributes of a stream. Passing `secret` rotates it (stored
     * re-encrypted); the new plaintext is revealed once on the returned object.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function update(string $id, array $attributes): RegisteredStream;

    /**
     * Disable a stream so it stops receiving deliveries (its pending rows remain).
     */
    public function disable(string $id): void;

    /**
     * The enabled streams, optionally narrowed to one `owner_key`. This is the
     * deny-by-default gate: an empty result means nothing is delivered.
     *
     * @return iterable<int, LogStream>
     */
    public function enabled(?string $ownerKey = null): iterable;

    public function find(string $id): ?LogStream;
}
