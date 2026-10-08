<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Cbox\LaravelSiem\Models\LogStream;
use Cbox\Siem\Contracts\StreamFormatter;
use Cbox\Siem\ValueObjects\StreamTarget;

/**
 * Builds the {@see StreamTarget} a sink receives for a stream — shared by the pump
 * and the test delivery so both ship exactly the same way. The target carries the
 * destination, auth scheme, formatter content type and gzip flag, the stream's
 * typed options (flattened; they are scalars by construction), and the secret,
 * decrypted in memory only for the sink to authenticate with.
 */
class StreamTargetFactory
{
    public function for(LogStream $stream, StreamFormatter $formatter): StreamTarget
    {
        $options = [];

        foreach ($stream->destinationOptions() as $key => $value) {
            if (is_scalar($value) || $value === null) {
                $options[$key] = $value;
            }
        }

        return new StreamTarget(
            name: $stream->name,
            endpoint: $stream->endpoint_url,
            options: [
                ...$options,
                'destination' => $stream->destination->value,
                'auth' => $stream->auth->value,
                'secret' => $stream->secret,
                'content_type' => $formatter->contentType(),
                'gzip' => array_key_exists('gzip', $options) ? $options['gzip'] : config('siem.http.gzip', false) === true,
            ],
        );
    }
}
