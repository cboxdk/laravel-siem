<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\ValueObjects\Options;

use Cbox\LaravelSiem\Enums\S3Encryption;
use Cbox\LaravelSiem\Exceptions\InvalidStreamConfiguration;
use Cbox\LaravelSiem\Support\OptionValues;

/**
 * The settings of an Amazon S3 (or S3-compatible) stream.
 *
 * Exactly one credential mode:
 *
 * - **Access key** — `access_key_id` here, the secret access key as the stream's
 *   (encrypted) secret.
 * - **Assumed role** — `role_arn` (+ `external_id`): the platform signs an STS
 *   `AssumeRole` call with ITS OWN identity (`siem.aws.*`) and writes with the
 *   short-lived credentials it gets back. The stream stores no secret at all.
 *
 * Everything else: `bucket`, `region`, an object-key `prefix`, optional
 * server-side encryption (`sse` = `AES256` | `aws:kms`, plus `kms_key_id`),
 * `path_style` addressing (default: virtual-hosted on AWS, path-style on a custom
 * endpoint), and `gzip` (default on).
 *
 * `new S3Options` is an inert placeholder (no bucket); real streams come from
 * {@see self::fromArray()}, which validates.
 */
readonly class S3Options
{
    private const string BUCKET = '/^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$/';

    private const string REGION = '/^[a-z0-9\-]{2,32}$/';

    private const string ACCESS_KEY_ID = '/^[A-Za-z0-9_\-+=.@]{3,128}$/';

    private const string ROLE_ARN = '/^arn:aws(-[a-z]+)*:iam::\d{12}:role\/[\w+=,.@\-\/]{1,512}$/';

    private const string EXTERNAL_ID = '/^[\w+=,.@:\/\-]{2,1224}$/';

    private const string KMS_KEY = '/^[A-Za-z0-9:\/_\-]{1,2048}$/';

    public function __construct(
        public string $bucket = '',
        public string $region = 'us-east-1',
        public string $prefix = '',
        public ?string $accessKeyId = null,
        public ?string $roleArn = null,
        public ?string $externalId = null,
        public ?S3Encryption $encryption = null,
        public ?string $kmsKeyId = null,
        public ?bool $pathStyle = null,
        public bool $gzip = true,
    ) {}

    /**
     * @param  array<array-key, mixed>  $options
     *
     * @throws InvalidStreamConfiguration
     */
    public static function fromArray(array $options): self
    {
        $accessKeyId = OptionValues::string($options, 'access_key_id', self::ACCESS_KEY_ID, 'Use the access key ID exactly as issued.');
        $roleArn = OptionValues::string($options, 'role_arn', self::ROLE_ARN, 'Expected arn:aws:iam::<account>:role/<name>.');

        if (($accessKeyId === null) === ($roleArn === null)) {
            throw InvalidStreamConfiguration::for('access_key_id', 'Give either an access key ID (with its secret) or a role ARN to assume — exactly one.');
        }

        $sse = OptionValues::string($options, 'sse');
        $encryption = $sse === null ? null : S3Encryption::tryFrom($sse);

        if ($sse !== null && $encryption === null) {
            throw InvalidStreamConfiguration::for('sse', 'Server-side encryption must be AES256 or aws:kms.');
        }

        $kmsKeyId = OptionValues::string($options, 'kms_key_id', self::KMS_KEY, 'Use a KMS key ID, alias or ARN.');

        if ($kmsKeyId !== null && $encryption !== S3Encryption::Kms) {
            throw InvalidStreamConfiguration::for('kms_key_id', 'A KMS key only applies with aws:kms server-side encryption.');
        }

        return new self(
            bucket: OptionValues::required($options, 'bucket', self::BUCKET, 'Bucket names are 3–63 lowercase letters, digits, dots and hyphens.'),
            region: strtolower(OptionValues::required($options, 'region', self::REGION, 'For example eu-west-1 (or "auto" for R2).')),
            prefix: OptionValues::prefix($options),
            accessKeyId: $accessKeyId,
            roleArn: $roleArn,
            externalId: OptionValues::string($options, 'external_id', self::EXTERNAL_ID, 'Use 2–1224 characters from [A-Za-z0-9+=,.@:/_-].'),
            encryption: $encryption,
            kmsKeyId: $kmsKeyId,
            pathStyle: OptionValues::bool($options, 'path_style'),
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
            'region' => $this->region,
            'prefix' => $this->prefix === '' ? null : $this->prefix,
            'access_key_id' => $this->accessKeyId,
            'role_arn' => $this->roleArn,
            'external_id' => $this->externalId,
            'sse' => $this->encryption?->value,
            'kms_key_id' => $this->kmsKeyId,
            'path_style' => $this->pathStyle,
            'gzip' => $this->gzip,
        ], static fn (string|bool|null $value): bool => $value !== null);
    }

    public function usesAssumedRole(): bool
    {
        return $this->roleArn !== null;
    }

    /**
     * The regional AWS endpoint, used when the stream has no custom endpoint.
     */
    public function defaultEndpoint(): string
    {
        return 'https://s3.'.$this->region.'.amazonaws.com';
    }

    public function withExternalId(string $externalId): self
    {
        return new self(
            $this->bucket, $this->region, $this->prefix, $this->accessKeyId, $this->roleArn,
            $externalId, $this->encryption, $this->kmsKeyId, $this->pathStyle, $this->gzip,
        );
    }
}
