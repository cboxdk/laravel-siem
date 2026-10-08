<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\ValueObjects\Options;

use Cbox\LaravelSiem\Enums\DatadogSite;
use Cbox\LaravelSiem\Exceptions\InvalidStreamConfiguration;
use Cbox\LaravelSiem\Support\OptionValues;

/**
 * The settings of a Datadog stream. The API key is the stream's (encrypted)
 * secret, never an option.
 *
 * - `site`     — the Datadog site the account lives on; selects the intake host.
 * - `service`  — the `service` attribute (defaults to `config('app.name')`).
 * - `source`   — the `ddsource` attribute (defaults to `siem.datadog.source`).
 * - `hostname` — the `hostname` attribute (defaults to the app URL's host).
 * - `tags`     — `ddtags`, comma-separated `key:value` tags.
 *
 * `new DatadogOptions` is a valid US1 stream with every attribute defaulted.
 */
readonly class DatadogOptions
{
    private const string NAME = '/^[A-Za-z0-9_.\-\/:]{1,100}$/';

    private const string HOST = '/^[A-Za-z0-9_.\-:]{1,255}$/';

    private const string TAG = '/^[A-Za-z][A-Za-z0-9_.\-:\/]{0,199}$/';

    public function __construct(
        public DatadogSite $site = DatadogSite::Us1,
        public ?string $service = null,
        public ?string $source = null,
        public ?string $hostname = null,
        public ?string $tags = null,
    ) {}

    /**
     * @param  array<array-key, mixed>  $options
     *
     * @throws InvalidStreamConfiguration
     */
    public static function fromArray(array $options): self
    {
        $site = OptionValues::string($options, 'site');
        $resolvedSite = $site === null ? DatadogSite::Us1 : DatadogSite::tryFrom(strtolower($site));

        if ($resolvedSite === null) {
            $sites = implode(', ', array_map(static fn (DatadogSite $s): string => $s->value, DatadogSite::cases()));

            throw InvalidStreamConfiguration::for('site', "Unknown Datadog site. Choose one of: {$sites}.");
        }

        return new self(
            site: $resolvedSite,
            service: OptionValues::string($options, 'service', self::NAME, 'Use letters, digits and _.-/: only.'),
            source: OptionValues::string($options, 'source', self::NAME, 'Use letters, digits and _.-/: only.'),
            hostname: OptionValues::string($options, 'hostname', self::HOST, 'Use a host name.'),
            tags: self::tags($options['tags'] ?? null),
        );
    }

    /**
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return array_filter([
            'site' => $this->site->value,
            'service' => $this->service,
            'source' => $this->source,
            'hostname' => $this->hostname,
            'tags' => $this->tags,
        ], static fn (?string $value): bool => $value !== null);
    }

    public function defaultEndpoint(): string
    {
        return $this->site->intakeUrl();
    }

    /**
     * Tags as a list or a comma-separated string, normalized to Datadog's
     * comma-separated `ddtags` form.
     */
    private static function tags(mixed $value): ?string
    {
        if ($value === null || $value === '' || $value === []) {
            return null;
        }

        $list = is_array($value) ? $value : (is_string($value) ? explode(',', $value) : null);

        if ($list === null) {
            throw InvalidStreamConfiguration::for('tags', 'The tags option must be a list or a comma-separated string.');
        }

        $tags = [];

        foreach ($list as $tag) {
            if (! is_string($tag)) {
                throw InvalidStreamConfiguration::for('tags', 'Every tag must be a string.');
            }

            $tag = trim($tag);

            if ($tag === '') {
                continue;
            }

            if (preg_match(self::TAG, $tag) !== 1) {
                throw InvalidStreamConfiguration::for('tags', 'A tag must start with a letter and use letters, digits and _.-:/ only (key:value).');
            }

            $tags[] = $tag;
        }

        if (count($tags) > 100) {
            throw InvalidStreamConfiguration::for('tags', 'At most 100 tags.');
        }

        return $tags === [] ? null : implode(',', $tags);
    }
}
