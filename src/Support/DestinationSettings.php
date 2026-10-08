<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Exceptions\InvalidStreamConfiguration;
use Cbox\LaravelSiem\ValueObjects\DestinationConfig;
use Cbox\LaravelSiem\ValueObjects\GcpServiceAccount;
use Cbox\LaravelSiem\ValueObjects\Options\DatadogOptions;
use Cbox\LaravelSiem\ValueObjects\Options\GcsOptions;
use Cbox\LaravelSiem\ValueObjects\Options\S3Options;
use SensitiveParameter;

/**
 * Validates and normalizes a stream's destination settings before the registry
 * stores them — deny-by-default: anything a destination does not accept is
 * refused with an {@see InvalidStreamConfiguration} naming the field.
 *
 * - HTTP collectors take the endpoint URL as given and no options.
 * - Cloud destinations take typed options; an empty endpoint means "the
 *   destination's own endpoint" (derived from the Datadog site / S3 region / GCS),
 *   and a custom endpoint (an S3-compatible store, a proxy, an emulator) must be
 *   `https`. Either way the caller still runs the endpoint through the SSRF guard.
 * - The secret is checked for the destination's credential mode (an API key, an
 *   S3 secret access key or none for an assumed role, a parseable service-account
 *   key). An assumed-role stream without an external ID gets a generated one.
 */
class DestinationSettings
{
    /**
     * @param  array<array-key, mixed>  $options
     *
     * @throws InvalidStreamConfiguration
     */
    public function normalize(
        Destination $destination,
        string $endpointUrl,
        array $options,
        #[SensitiveParameter] ?string $secret,
    ): DestinationConfig {
        $endpointUrl = trim($endpointUrl);

        if (! $destination->requiresOptions()) {
            if ($options !== []) {
                throw InvalidStreamConfiguration::for('options', "The {$destination->value} destination takes no options.");
            }

            if ($endpointUrl === '') {
                throw InvalidStreamConfiguration::for('endpoint_url', 'An endpoint URL is required.');
            }

            return new DestinationConfig($endpointUrl);
        }

        $hasSecret = $secret !== null && $secret !== '';

        [$default, $normalized] = match ($destination) {
            Destination::Datadog => $this->datadog($options, $hasSecret),
            Destination::S3 => $this->s3($options, $hasSecret),
            Destination::Gcs => $this->gcs($options, $secret),
            default => throw InvalidStreamConfiguration::for('destination', "The {$destination->value} destination has no typed options."),
        };

        return new DestinationConfig($this->endpoint($endpointUrl, $default), $normalized);
    }

    /**
     * The endpoint a cloud destination derives from its options (the Datadog
     * site's intake, the S3 region's endpoint, Google's storage host), or null
     * for an HTTP collector or options that do not parse.
     *
     * @param  array<array-key, mixed>  $options
     */
    public function defaultEndpoint(Destination $destination, array $options): ?string
    {
        try {
            return match ($destination) {
                Destination::Datadog => DatadogOptions::fromArray($options)->defaultEndpoint(),
                Destination::S3 => S3Options::fromArray($options)->defaultEndpoint(),
                Destination::Gcs => GcsOptions::fromArray($options)->defaultEndpoint(),
                default => null,
            };
        } catch (InvalidStreamConfiguration) {
            return null;
        }
    }

    /**
     * @param  array<array-key, mixed>  $options
     * @return array{string, array<string, string|bool>}
     */
    private function datadog(array $options, bool $hasSecret): array
    {
        $parsed = DatadogOptions::fromArray($options);

        if (! $hasSecret) {
            throw InvalidStreamConfiguration::for('secret', 'A Datadog stream needs an API key as its secret.');
        }

        return [$parsed->defaultEndpoint(), $parsed->toArray()];
    }

    /**
     * @param  array<array-key, mixed>  $options
     * @return array{string, array<string, string|bool>}
     */
    private function s3(array $options, bool $hasSecret): array
    {
        $parsed = S3Options::fromArray($options);

        if ($parsed->usesAssumedRole()) {
            if ($hasSecret) {
                throw InvalidStreamConfiguration::for('secret', 'An assumed-role S3 stream stores no secret — the platform assumes the role with its own identity.');
            }

            // Confused-deputy protection: every assumed-role stream gets an external
            // ID the customer's trust policy must require, unique to this stream.
            if ($parsed->externalId === null) {
                $parsed = $parsed->withExternalId(bin2hex(random_bytes(16)));
            }
        } elseif (! $hasSecret) {
            throw InvalidStreamConfiguration::for('secret', 'An access-key S3 stream needs the secret access key as its secret.');
        }

        return [$parsed->defaultEndpoint(), $parsed->toArray()];
    }

    /**
     * @param  array<array-key, mixed>  $options
     * @return array{string, array<string, string|bool>}
     */
    private function gcs(array $options, #[SensitiveParameter] ?string $secret): array
    {
        $parsed = GcsOptions::fromArray($options);
        GcpServiceAccount::fromJson($secret);

        return [$parsed->defaultEndpoint(), $parsed->toArray()];
    }

    private function endpoint(string $endpointUrl, string $default): string
    {
        if ($endpointUrl === '') {
            return $default;
        }

        $parts = parse_url($endpointUrl);

        if (! is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || ($parts['host'] ?? '') === '') {
            throw InvalidStreamConfiguration::for('endpoint_url', 'A custom endpoint must be an https:// URL.');
        }

        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw InvalidStreamConfiguration::for('endpoint_url', 'A custom endpoint may not carry credentials, a query or a fragment.');
        }

        return rtrim($endpointUrl, '/');
    }
}
