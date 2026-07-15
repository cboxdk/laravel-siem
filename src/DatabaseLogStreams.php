<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem;

use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Enums\AuthScheme;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\Models\LogStream;
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
    public function create(
        string $name,
        Destination $destination,
        string $endpointUrl,
        ?string $secret = null,
        ?AuthScheme $auth = null,
        ?string $ownerKey = null,
        array $filters = [],
        array $redaction = [],
    ): RegisteredStream {
        // SSRF guard at registration: refuse an endpoint that points at a
        // non-public address before it is ever stored.
        SafeStreamUrl::assert($endpointUrl);

        $scheme = $auth ?? $destination->defaultAuth();

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
            'endpoint_url' => $endpointUrl,
            'secret' => $secret,
            'auth' => $scheme,
            'owner_key' => $ownerKey,
            'filters' => $filters === [] ? null : $filters,
            'redaction' => $redaction === [] ? null : $redaction,
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

        $endpoint = $attributes['endpoint_url'] ?? null;
        if (is_string($endpoint)) {
            SafeStreamUrl::assert($endpoint);
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
     * @return class-string<LogStream>
     */
    private function modelClass(): string
    {
        return ModelClass::resolve('siem.models.log_stream', LogStream::class);
    }
}
