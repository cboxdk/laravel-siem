<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\ValueObjects\Options;

use Cbox\LaravelSiem\Exceptions\InvalidStreamConfiguration;
use Cbox\LaravelSiem\Support\OptionValues;

/**
 * The settings of a Google Cloud Storage stream: the `bucket`, an object-key
 * `prefix`, and `gzip` (default on). The service-account JSON key is the stream's
 * (encrypted) secret, never an option.
 *
 * `new GcsOptions` is an inert placeholder (no bucket); real streams come from
 * {@see self::fromArray()}, which validates.
 */
readonly class GcsOptions
{
    private const string BUCKET = '/^[a-z0-9][a-z0-9._\-]{1,220}[a-z0-9]$/';

    public function __construct(
        public string $bucket = '',
        public string $prefix = '',
        public bool $gzip = true,
    ) {}

    /**
     * @param  array<array-key, mixed>  $options
     *
     * @throws InvalidStreamConfiguration
     */
    public static function fromArray(array $options): self
    {
        return new self(
            bucket: OptionValues::required($options, 'bucket', self::BUCKET, 'Bucket names are lowercase letters, digits, dots, hyphens and underscores.'),
            prefix: OptionValues::prefix($options),
            gzip: OptionValues::bool($options, 'gzip') ?? true,
        );
    }

    /**
     * @return array<string, string|bool>
     */
    public function toArray(): array
    {
        return array_filter([
            'bucket' => $this->bucket,
            'prefix' => $this->prefix === '' ? null : $this->prefix,
            'gzip' => $this->gzip,
        ], static fn (string|bool|null $value): bool => $value !== null);
    }

    public function defaultEndpoint(): string
    {
        return 'https://storage.googleapis.com';
    }
}
