<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Contracts;

use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\LaravelSiem\ValueObjects\AwsCredentials;
use Cbox\LaravelSiem\ValueObjects\Options\S3Options;
use SensitiveParameter;

/**
 * Supplies the AWS credentials an S3 stream signs with. The default resolver
 * handles the two modes a stream can be configured with — a static access key, or
 * an STS `AssumeRole` performed with the platform's own identity (`siem.aws.*`).
 *
 * Rebind this to plug in another source, e.g. an adapter over the AWS SDK's
 * default provider chain (instance profile, ECS task role, web identity) for a
 * single-tenant install. Never resolve a multi-tenant customer's stream to the
 * platform's ambient instance role: that would let a customer write with the
 * platform's permissions (a confused deputy).
 */
interface AwsCredentialResolver
{
    /**
     * @throws DestinationRefused when the credentials are refused or not configured
     * @throws StreamDeliveryFailed on a transient failure (e.g. STS unreachable)
     */
    public function resolve(S3Options $options, #[SensitiveParameter] ?string $secret): AwsCredentials;

    /**
     * Drop any cached credentials for these options (after the destination said
     * they expired or were refused), so the next resolve fetches fresh ones.
     */
    public function forget(S3Options $options): void;
}
