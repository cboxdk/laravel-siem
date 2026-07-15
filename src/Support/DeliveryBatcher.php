<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Cbox\LaravelSiem\Models\StreamDelivery;

/**
 * Cuts a run of claimed outbox rows into delivery batches, each bounded three ways
 * at once: at most `maxRecords` rows, at most `maxBytes` of payload, and spanning
 * at most `maxAgeSeconds` between its first and last row. Whichever bound trips
 * first ends the current batch and starts the next — so one HTTP request can never
 * exceed a destination's record or size limit, nor hold events past the latency
 * budget. A single row larger than `maxBytes` still ships alone (one event is
 * never split).
 */
class DeliveryBatcher
{
    /**
     * @param  list<StreamDelivery>  $rows
     * @return list<list<StreamDelivery>>
     */
    public function batch(array $rows, int $maxRecords, int $maxBytes, int $maxAgeSeconds): array
    {
        $maxRecords = max(1, $maxRecords);
        $maxBytes = max(1, $maxBytes);
        $maxAgeSeconds = max(0, $maxAgeSeconds);

        /** @var list<list<StreamDelivery>> $batches */
        $batches = [];
        /** @var list<StreamDelivery> $current */
        $current = [];
        $currentBytes = 0;
        $firstAt = null;

        foreach ($rows as $row) {
            $size = $this->sizeOf($row);
            $createdAt = $row->created_at?->getTimestamp();

            $wouldOverflow = $current !== [] && (
                count($current) >= $maxRecords
                || $currentBytes + $size > $maxBytes
                || ($firstAt !== null && $createdAt !== null && $createdAt - $firstAt > $maxAgeSeconds)
            );

            if ($wouldOverflow) {
                $batches[] = $current;
                $current = [];
                $currentBytes = 0;
                $firstAt = null;
            }

            if ($current === []) {
                $firstAt = $createdAt;
            }

            $current[] = $row;
            $currentBytes += $size;
        }

        if ($current !== []) {
            $batches[] = $current;
        }

        return $batches;
    }

    private function sizeOf(StreamDelivery $row): int
    {
        $encoded = json_encode($row->payload);

        return $encoded === false ? 0 : strlen($encoded);
    }
}
