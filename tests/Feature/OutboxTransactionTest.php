<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Models\StreamDelivery;
use Cbox\LaravelSiem\Tests\Fixtures\EventFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

beforeEach(fn () => config(['siem.http.verify_url' => false]));

it('writes the outbox row inside the caller transaction (at-least-once framing)', function (): void {
    $registered = $this->createLogStream('json', Destination::GenericJson, 'https://collector.example.test');

    // The dispatch happens in the caller's transaction; if the caller rolls back,
    // the intent-to-deliver row rolls back with it — no orphan delivery.
    try {
        DB::transaction(function () use ($registered): void {
            app(StreamDispatcher::class)->dispatch(EventFactory::make(), [$registered->stream]);

            throw new RuntimeException('caller failed after dispatch');
        });
    } catch (RuntimeException) {
        // expected
    }

    expect(StreamDelivery::query()->count())->toBe(0);
});

it('keeps the outbox row when the caller transaction commits', function (): void {
    $registered = $this->createLogStream('json', Destination::GenericJson, 'https://collector.example.test');

    DB::transaction(function () use ($registered): void {
        app(StreamDispatcher::class)->dispatch(EventFactory::make(), [$registered->stream]);
    });

    expect(StreamDelivery::query()->where('status', 'pending')->count())->toBe(1);
});
