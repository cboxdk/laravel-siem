<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Tests\Fixtures\EventFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(fn () => config(['siem.http.verify_url' => false]));

it('never ships more than max_records in a single batch', function (): void {
    config(['siem.batch.max_records' => 2]);

    $sink = $this->fakeStreamSink();
    $registered = $this->createLogStream('json', Destination::GenericJson, 'https://collector.example.test');

    $dispatcher = app(StreamDispatcher::class);
    foreach (range(1, 5) as $i) {
        $dispatcher->dispatch(EventFactory::make(id: "evt_{$i}"), [$registered->stream]);
    }

    $this->pumpStream($registered->stream->id);

    // 5 events, cap 2 → batches of 2, 2, 1.
    expect($sink->batches())->toHaveCount(3);
    foreach ($sink->batches() as $batch) {
        expect(count($batch['records']))->toBeLessThanOrEqual(2);
    }
    expect($sink->records())->toHaveCount(5);
});
