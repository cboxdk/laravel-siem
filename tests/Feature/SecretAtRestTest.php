<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Enums\AuthScheme;
use Cbox\LaravelSiem\Enums\Destination;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

beforeEach(fn () => config(['siem.http.verify_url' => false]));

it('stores the secret as ciphertext, not the plaintext token', function (): void {
    $registered = $this->createLogStream('splunk', Destination::SplunkHec, 'https://hec.example.test', secret: 'super-secret-token');

    /** @var object{secret: string} $raw */
    $raw = DB::table('log_streams')->where('id', $registered->stream->id)->first();

    expect($raw->secret)->not->toBe('super-secret-token')
        ->and($raw->secret)->not->toContain('super-secret-token')
        // The model transparently decrypts it back.
        ->and($registered->stream->fresh()->secret)->toBe('super-secret-token')
        // Revealed exactly once at creation.
        ->and($registered->secret)->toBe('super-secret-token');
});

it('generates and reveals an HMAC signing key once when none is supplied', function (): void {
    $registered = $this->createLogStream(
        'json',
        Destination::GenericJson,
        'https://collector.example.test',
        auth: AuthScheme::Hmac,
    );

    expect($registered->secret)->toBeString()->toHaveLength(64)
        ->and($registered->stream->fresh()->secret)->toBe($registered->secret);
});
