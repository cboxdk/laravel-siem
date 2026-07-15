<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Models\StreamDelivery;
use Cbox\LaravelSiem\Support\DeliveryBatcher;
use Illuminate\Support\Carbon;

/**
 * @param  array<string, mixed>  $payload
 */
function makeRow(array $payload, ?Carbon $createdAt = null): StreamDelivery
{
    $row = new StreamDelivery;
    $row->payload = $payload;
    $row->created_at = $createdAt ?? Carbon::parse('2026-07-15 12:00:00');

    return $row;
}

it('never puts more than max_records in a batch', function (): void {
    $rows = array_map(fn (int $i) => makeRow(['n' => $i]), range(1, 5));

    $batches = (new DeliveryBatcher)->batch($rows, maxRecords: 2, maxBytes: PHP_INT_MAX, maxAgeSeconds: 3600);

    expect($batches)->toHaveCount(3);
    foreach ($batches as $batch) {
        expect(count($batch))->toBeLessThanOrEqual(2);
    }
});

it('never exceeds max_bytes within a batch (except a lone oversized row)', function (): void {
    // Each payload serializes to well over 20 bytes, so each row is its own batch.
    $rows = array_map(fn (int $i) => makeRow(['blob' => str_repeat('x', 50), 'n' => $i]), range(1, 4));

    $batches = (new DeliveryBatcher)->batch($rows, maxRecords: 1000, maxBytes: 20, maxAgeSeconds: 3600);

    expect($batches)->toHaveCount(4);
});

it('cuts a batch when it spans more than max_age', function (): void {
    $rows = [
        makeRow(['n' => 1], Carbon::parse('2026-07-15 12:00:00')),
        makeRow(['n' => 2], Carbon::parse('2026-07-15 12:00:03')),
        makeRow(['n' => 3], Carbon::parse('2026-07-15 12:00:20')), // >5s after the first
    ];

    $batches = (new DeliveryBatcher)->batch($rows, maxRecords: 1000, maxBytes: PHP_INT_MAX, maxAgeSeconds: 5);

    expect($batches)->toHaveCount(2)
        ->and($batches[0])->toHaveCount(2)
        ->and($batches[1])->toHaveCount(1);
});
