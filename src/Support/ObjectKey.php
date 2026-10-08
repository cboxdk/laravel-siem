<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use Illuminate\Support\Str;

/**
 * The object-storage layout every batch is written under:
 *
 *     {prefix}/{yyyy}/{mm}/{dd}/{hh}/{batch-id}.ndjson[.gz]
 *
 * Partitioned by the UTC hour the batch was WRITTEN (not by event time — a batch
 * retried later lands in a later partition; dedup by event id, as with every
 * at-least-once stream). The batch id is a lowercase ULID, so object names sort by
 * write time within a partition and never collide — a retry writes a new object
 * rather than overwriting, which keeps write-only permissions (no delete or
 * overwrite) sufficient.
 */
final class ObjectKey
{
    public static function make(string $prefix, DateTimeInterface $at, bool $gzip, ?string $batchId = null): string
    {
        $utc = DateTimeImmutable::createFromInterface($at)->setTimezone(new DateTimeZone('UTC'));
        $id = $batchId ?? strtolower((string) Str::ulid());
        $path = $utc->format('Y/m/d/H').'/'.$id.'.ndjson'.($gzip ? '.gz' : '');

        return $prefix === '' ? $path : $prefix.'/'.$path;
    }

    /**
     * The key, URI-encoded per segment for use in a request path.
     */
    public static function encode(string $key): string
    {
        return implode('/', array_map(rawurlencode(...), explode('/', $key)));
    }
}
