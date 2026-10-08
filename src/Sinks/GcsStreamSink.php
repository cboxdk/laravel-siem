<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Sinks;

use Cbox\LaravelSiem\Contracts\GcsAccessTokens;
use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\InvalidStreamConfiguration;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\Support\Egress;
use Cbox\LaravelSiem\Support\ObjectKey;
use Cbox\LaravelSiem\Support\SecretScrubber;
use Cbox\LaravelSiem\ValueObjects\GcpServiceAccount;
use Cbox\LaravelSiem\ValueObjects\Options\GcsOptions;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\ValueObjects\StreamTarget;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * Writes each batch to Google Cloud Storage as ONE newline-delimited JSON object,
 * gzip-compressed by default, under the same layout as S3
 * (`{prefix}/{yyyy}/{mm}/{dd}/{hh}/{batch-id}.ndjson.gz`, see {@see ObjectKey}),
 * with the JSON API's simple media upload.
 *
 * Authorization is a bearer access token from {@see GcsAccessTokens}, obtained with
 * the stream's service-account key (its encrypted secret) and cached. The upload
 * and the token exchange both go through {@see Egress}.
 *
 * Failure mapping: 401 drops the cached token and is an authentication refusal
 * (the next attempt after the cooldown re-exchanges the key); 403 means the
 * account lacks `storage.objects.create` on the bucket; 404 means no such bucket.
 * Those three are {@see DestinationRefused}; everything else is transient.
 */
class GcsStreamSink implements StreamSink
{
    public function __construct(
        private readonly GcsAccessTokens $tokens,
        private readonly Egress $egress = new Egress,
        private readonly SecretScrubber $scrubber = new SecretScrubber,
    ) {}

    public function send(iterable $formattedRecords, StreamTarget $target): void
    {
        $records = [];
        foreach ($formattedRecords as $record) {
            $records[] = $record;
        }

        if ($records === []) {
            return;
        }

        $secret = SinkOptions::string($target, 'secret');

        try {
            $options = GcsOptions::fromArray($target->options);
            $account = GcpServiceAccount::fromJson($secret);
        } catch (InvalidStreamConfiguration $e) {
            throw DestinationRefused::configuration($e->getMessage(), $e);
        }

        $body = implode("\n", $records)."\n";
        $payload = $options->gzip ? (gzencode($body) ?: $body) : $body;
        $gzip = $options->gzip && $payload !== $body;
        $key = ObjectKey::make($options->prefix, Carbon::now(), $gzip);

        $base = rtrim($target->endpoint === '' ? $options->defaultEndpoint() : $target->endpoint, '/');
        $url = $base.'/upload/storage/v1/b/'.rawurlencode($options->bucket).'/o?uploadType=media&name='.rawurlencode($key);

        $token = $this->tokens->token($account);
        $secrets = [$secret, $account->privateKey, $token];

        $response = $this->egress->send(
            'POST',
            $url,
            ['Authorization' => 'Bearer '.$token],
            $payload,
            $gzip ? 'application/gzip' : 'application/x-ndjson',
            $secrets,
        );

        if (! $response->successful()) {
            throw $this->failure($response, $options, $account, $secrets);
        }
    }

    /**
     * @param  list<string|null>  $secrets
     */
    private function failure(Response $response, GcsOptions $options, GcpServiceAccount $account, array $secrets): StreamDeliveryFailed
    {
        $status = $response->status();
        $reason = $response->json('error.message');
        $detail = is_string($reason) ? Str::limit(preg_replace('/\s+/', ' ', $reason) ?? '', 300) : '';

        if ($status === 401) {
            $this->tokens->forget($account);

            return DestinationRefused::authentication($this->scrubber->scrubAll(trim("Google Cloud Storage refused the access token for bucket [{$options->bucket}] (HTTP 401). {$detail}"), $secrets));
        }

        return match ($status) {
            403 => DestinationRefused::authentication($this->scrubber->scrubAll(trim("The service account {$account->clientEmail} may not write to bucket [{$options->bucket}] (HTTP 403) — grant it roles/storage.objectCreator. {$detail}"), $secrets)),
            404 => DestinationRefused::configuration($this->scrubber->scrubAll(trim("Google Cloud Storage has no bucket [{$options->bucket}] (HTTP 404). {$detail}"), $secrets)),
            default => $this->egress->failure($response, 'Google Cloud Storage', $secrets, $detail),
        };
    }
}
