<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Support\Redactor;
use Cbox\LaravelSiem\Tests\Fixtures\EventFactory;

it('drops, masks, and hashes matched fields and leaves others intact', function (): void {
    $event = EventFactory::make(context: [
        'password' => 'hunter2',
        'email' => 'alice@example.com',
        'card' => '4242424242424242',
        'plan' => 'pro',
    ]);

    $redacted = (new Redactor)->redact($event, [
        'password' => 'drop',
        'email' => 'hash',
        'card' => 'mask',
    ]);

    expect($redacted->context)->not->toHaveKey('password')
        ->and($redacted->context['email'])->toBe(hash('sha256', 'alice@example.com'))
        ->and($redacted->context['card'])->toBe('[REDACTED]')
        ->and($redacted->context['plan'])->toBe('pro');
});

it('can redact top-level message and source_ip', function (): void {
    $event = EventFactory::make();

    $redacted = (new Redactor)->redact($event, [
        'message' => 'drop',
        'source_ip' => 'hash',
    ]);

    expect($redacted->message)->toBeNull()
        ->and($redacted->sourceIp)->toBe(hash('sha256', '203.0.113.10'));
});

it('returns the same event when the policy is empty', function (): void {
    $event = EventFactory::make(context: ['a' => 'b']);

    expect((new Redactor)->redact($event, [])->context)->toBe(['a' => 'b']);
});
