<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem;

use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Enums\AuthScheme;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Exceptions\InvalidStreamConfiguration;
use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\Support\CircuitBreaker;
use Cbox\LaravelSiem\Support\DestinationSettings;
use Cbox\LaravelSiem\Support\ModelClass;
use Cbox\LaravelSiem\Support\SafeStreamUrl;
use Cbox\LaravelSiem\ValueObjects\RegisteredStream;

/**
 * The default Eloquent-backed {@see LogStreams} registry. Tenancy-agnostic: it
 * filters by the opaque `owner_key` only when the caller passes one, and assigns
 * that key no meaning. The stream model is resolved through `config('siem.models')`
 * so a host can subclass it (e.g. to add an environment scope).
 */
class DatabaseLogStreams implements LogStreams
{
    /**
     * The attributes that make up a stream's destination settings: changing any
     * of them re-validates the whole set and resets the breaker.
     */
    private const array SETTINGS = ['destination', 'endpoint_url', 'options', 'secret'];

    public function __construct(
        private readonly DestinationSettings $settings = new DestinationSettings,
        private readonly CircuitBreaker $breaker = new CircuitBreaker,
    ) {}

    public function create(
        string $name,
        Destination $destination,
        string $endpointUrl,
        ?string $secret = null,
        ?AuthScheme $auth = null,
        ?string $ownerKey = null,
        array $filters = [],
        array $redaction = [],
        array $options = [],
    ): RegisteredStream {
        // Validate the destination settings (deny-by-default) and derive a cloud
        // destination's endpoint, then SSRF-guard whatever will be dialled: refuse
        // an endpoint that points at a non-public address before it is stored.
        $config = $this->settings->normalize($destination, $endpointUrl, $options, $secret);
        SafeStreamUrl::assert($config->endpoint);

        // The cloud destinations authenticate their own way; no generic scheme.
        $scheme = $destination->requiresOptions() ? AuthScheme::None : ($auth ?? $destination->defaultAuth());

        // Generate a signing key when the scheme needs a package-owned secret and
        // none was supplied (HEC/bearer tokens are operator-supplied instead).
        if ($secret === null && $scheme === AuthScheme::Hmac) {
            $secret = bin2hex(random_bytes(32));
        }

        $class = $this->modelClass();
        $stream = new $class;
        $stream->fill([
            'name' => $name,
            'destination' => $destination,
            'endpoint_url' => $config->endpoint,
            'secret' => $secret,
            'auth' => $scheme,
            'owner_key' => $ownerKey,
            'filters' => $filters === [] ? null : $filters,
            'redaction' => $redaction === [] ? null : $redaction,
            'options' => $config->options === [] ? null : $config->options,
            'enabled' => true,
            'consecutive_failures' => 0,
        ]);
        $stream->save();

        // Reveal the effective plaintext secret exactly once; only ciphertext is
        // persisted (the `encrypted` cast).
        return new RegisteredStream($stream, $secret);
    }

    public function update(string $id, array $attributes): RegisteredStream
    {
        $stream = $this->modelClass()::query()->findOrFail($id);

        if (array_intersect(self::SETTINGS, array_keys($attributes)) !== []) {
            $attributes = $this->revalidate($stream, $attributes);
            $this->breaker->reset($stream);
        }

        $stream->fill($attributes);
        $stream->save();

        $revealed = $attributes['secret'] ?? null;

        return new RegisteredStream($stream, is_string($revealed) ? $revealed : null);
    }

    public function disable(string $id): void
    {
        $this->modelClass()::query()->whereKey($id)->update(['enabled' => false]);
    }

    public function enabled(?string $ownerKey = null): iterable
    {
        return $this->modelClass()::query()
            ->where('enabled', true)
            ->when($ownerKey !== null, fn ($query) => $query->where('owner_key', $ownerKey))
            ->get()
            ->all();
    }

    public function find(string $id): ?LogStream
    {
        return $this->modelClass()::query()->find($id);
    }

    /**
     * Merge the changed settings over the stored ones, validate the result as a
     * whole, and return the attributes to write (normalized endpoint/options).
     *
     * @param  array<string, mixed>  $attributes
     * @return array<string, mixed>
     */
    private function revalidate(LogStream $stream, array $attributes): array
    {
        $destination = $attributes['destination'] ?? $stream->destination;
        $destination = $destination instanceof Destination ? $destination : Destination::tryFrom(is_string($destination) ? $destination : '');

        if ($destination === null) {
            throw InvalidStreamConfiguration::for('destination', 'Unknown destination.');
        }

        $endpoint = $attributes['endpoint_url'] ?? $stream->endpoint_url;
        $options = array_key_exists('options', $attributes) ? $attributes['options'] : $stream->destinationOptions();
        $secret = array_key_exists('secret', $attributes) ? $attributes['secret'] : $stream->secret;

        // A stream on its destination's OWN endpoint (derived from the site or
        // region) follows its settings: change the Datadog site or the S3 region,
        // or switch destination, and the endpoint is derived afresh (switching to
        // an HTTP collector then requires a new endpoint URL). Only an explicitly
        // custom endpoint is kept.
        if (! array_key_exists('endpoint_url', $attributes)
            && $stream->endpoint_url === $this->settings->defaultEndpoint($stream->destination, $stream->destinationOptions())) {
            $endpoint = '';
        }

        $config = $this->settings->normalize(
            $destination,
            is_string($endpoint) ? $endpoint : '',
            is_array($options) ? $options : [],
            is_string($secret) ? $secret : null,
        );
        SafeStreamUrl::assert($config->endpoint);

        $attributes['destination'] = $destination;
        $attributes['endpoint_url'] = $config->endpoint;
        $attributes['options'] = $config->options === [] ? null : $config->options;

        if ($destination->requiresOptions()) {
            $attributes['auth'] = AuthScheme::None;
        }

        return $attributes;
    }

    /**
     * @return class-string<LogStream>
     */
    private function modelClass(): string
    {
        return ModelClass::resolve('siem.models.log_stream', LogStream::class);
    }
}
