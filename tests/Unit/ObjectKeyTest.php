<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Support\ObjectKey;
use Cbox\LaravelSiem\Support\SecretScrubber;

it('partitions object keys by the UTC hour of the write', function (): void {
    $at = new DateTimeImmutable('2026-10-08T01:30:00+02:00'); // 2026-10-07 23:30 UTC

    expect(ObjectKey::make('cbox/audit', $at, true, '01jabc'))->toBe('cbox/audit/2026/10/07/23/01jabc.ndjson.gz')
        ->and(ObjectKey::make('', $at, false, '01jabc'))->toBe('2026/10/07/23/01jabc.ndjson');
});

it('gives every batch a distinct, sortable id', function (): void {
    $at = new DateTimeImmutable('2026-10-08T14:00:00Z');

    expect(ObjectKey::make('p', $at, true))->not->toBe(ObjectKey::make('p', $at, true))
        ->and(ObjectKey::make('p', $at, true))->toMatch('#^p/2026/10/08/14/[0-9a-z]{26}\.ndjson\.gz$#');
});

it('scrubs every named secret, longest first', function (): void {
    $message = 'key=abc123 token=abc123-session json={"private_key":"abc123"}';

    expect((new SecretScrubber)->scrubAll($message, ['abc123', 'abc123-session', null]))
        ->toBe('key=[redacted-secret] token=[redacted-secret] json={"private_key":"[redacted-secret]"}');
});
