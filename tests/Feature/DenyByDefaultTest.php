<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Models\StreamDelivery;
use Cbox\LaravelSiem\Tests\Fixtures\EventFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('delivers nothing when no stream is configured', function (): void {
    $written = app(StreamDispatcher::class)->dispatch(EventFactory::make(), []);

    expect($written)->toBe(0)
        ->and(StreamDelivery::query()->count())->toBe(0);
});

it('writes nothing for a disabled stream', function (): void {
    config(['siem.http.verify_url' => false]);

    $registered = $this->createLogStream('splunk', Destination::SplunkHec, 'https://hec.example.test', secret: 'token');
    app(LogStreams::class)->disable($registered->stream->id);

    $written = app(StreamDispatcher::class)->dispatch(EventFactory::make(), [$registered->stream->fresh()]);

    expect($written)->toBe(0)
        ->and(StreamDelivery::query()->count())->toBe(0);
});

it('skips an event the stream action filter denies', function (): void {
    config(['siem.http.verify_url' => false]);

    $registered = $this->createLogStream(
        'json',
        Destination::GenericJson,
        'https://collector.example.test',
        filters: ['allow' => ['role-granted']],
    );

    $written = app(StreamDispatcher::class)->dispatch(EventFactory::make(action: 'user-login'), [$registered->stream]);

    expect($written)->toBe(0)
        ->and(StreamDelivery::query()->count())->toBe(0);
});
