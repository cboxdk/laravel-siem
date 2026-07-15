<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Tests\Fixtures\EventFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(fn () => config(['siem.http.verify_url' => false]));

it('redacts sensitive fields before they reach the sink', function (): void {
    $sink = $this->fakeStreamSink();

    $registered = $this->createLogStream(
        'json',
        Destination::GenericJson,
        'https://collector.example.test',
        redaction: ['password' => 'drop', 'email' => 'hash'],
    );

    app(StreamDispatcher::class)->dispatch(
        EventFactory::make(context: ['password' => 'hunter2', 'email' => 'alice@example.com', 'plan' => 'pro']),
        [$registered->stream],
    );

    $this->pumpStream($registered->stream->id);

    $records = $sink->records();
    expect($records)->toHaveCount(1);

    $record = $records[0];
    // The raw values never reach the transport...
    expect($record)->not->toContain('hunter2')
        ->and($record)->not->toContain('alice@example.com')
        // ...but the hash of the email and the untouched field do.
        ->and($record)->toContain(hash('sha256', 'alice@example.com'))
        ->and($record)->toContain('pro');

    // And the batch really went to the configured stream.
    $sink->assertSentTo('json');
});
