<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\Support\ModelClass;

it('returns the base model when the config is unset', function (): void {
    config(['siem.models.log_stream' => null]);

    expect(ModelClass::resolve('siem.models.log_stream', LogStream::class))
        ->toBe(LogStream::class);
});

it('returns a configured subclass', function (): void {
    $subclass = new class extends LogStream {};
    config(['siem.models.log_stream' => $subclass::class]);

    expect(ModelClass::resolve('siem.models.log_stream', LogStream::class))
        ->toBe($subclass::class);
});

it('FAILS CLOSED on a set-but-invalid model config instead of silently using the base', function (): void {
    // A host that isolation-scopes via a subclass must never be silently downgraded
    // to the unscoped base model — that would open the tenant boundary. A wrong
    // value is a hard error, not a fallback.
    config(['siem.models.log_stream' => 'Some\\Bogus\\NotAModel']);

    expect(fn () => ModelClass::resolve('siem.models.log_stream', LogStream::class))
        ->toThrow(InvalidArgumentException::class);
});

it('also fails closed on a non-string model config', function (): void {
    config(['siem.models.log_stream' => 123]);

    expect(fn () => ModelClass::resolve('siem.models.log_stream', LogStream::class))
        ->toThrow(InvalidArgumentException::class);
});
