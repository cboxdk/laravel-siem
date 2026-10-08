---
title: Stream to Amazon S3
weight: 4
description: Archive events to Amazon S3 (or MinIO / Cloudflare R2) as time-partitioned NDJSON objects — least-privilege IAM, access keys or an assumed role, and server-side encryption.
---

# Stream to Amazon S3

Each batch becomes one object:

```
{prefix}/{yyyy}/{mm}/{dd}/{hh}/{batch-id}.ndjson.gz
```

partitioned by the UTC hour it was written, one JSON event per line, gzip by default
(`gzip => false` writes `.ndjson`). The batch id is a fresh ULID, so a retry writes a
new object instead of overwriting one — `s3:PutObject` alone is enough.

## 1. Least-privilege policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SiemWriteOnly",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::acme-audit-logs/cbox/audit/*"
    }
  ]
}
```

With SSE-KMS on a customer-managed key, also allow `kms:GenerateDataKey` on that key.
No `s3:GetObject`, `s3:ListBucket` or `s3:DeleteObject` is needed.

## 2a. Access key

Create an IAM user with only that policy and register the stream with its key:

```php
app(LogStreams::class)->create(
    name: 's3-archive',
    destination: Destination::S3,
    endpointUrl: '',                       // https://s3.<region>.amazonaws.com
    secret: 'the-secret-access-key',       // stored encrypted
    options: [
        'bucket' => 'acme-audit-logs',
        'region' => 'eu-west-1',
        'prefix' => 'cbox/audit',
        'access_key_id' => 'AKIA…',
    ],
);
```

## 2b. Assumed role (no customer secret stored)

The platform calls STS `AssumeRole` with **its own** AWS identity and writes with the
temporary credentials it gets back (cached, encrypted, until five minutes before
they expire).

1. Configure the platform identity once (`.env`): `SIEM_AWS_ACCESS_KEY_ID`,
   `SIEM_AWS_SECRET_ACCESS_KEY`. It needs only `sts:AssumeRole`.
2. Register the stream with a `role_arn` and no secret. An `external_id` is
   generated (or pass your own) — show it to whoever creates the role:

```php
$registered = app(LogStreams::class)->create(
    name: 's3-archive',
    destination: Destination::S3,
    endpointUrl: '',
    options: [
        'bucket' => 'acme-audit-logs',
        'region' => 'eu-west-1',
        'prefix' => 'cbox/audit',
        'role_arn' => 'arn:aws:iam::123456789012:role/siem-writer',
    ],
);

$externalId = $registered->stream->destinationOptions()['external_id'];
```

3. The role carries the policy from step 1 and this trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<platform-account-id>:user/<platform-user>" },
      "Action": "sts:AssumeRole",
      "Condition": { "StringEquals": { "sts:ExternalId": "<external_id>" } }
    }
  ]
}
```

The external ID is what stops one customer from pointing a stream at a role another
customer created for the platform (the confused-deputy problem), so it is unique per
stream.

## Server-side encryption

`'sse' => 'AES256'` or `'sse' => 'aws:kms'` (optionally with `'kms_key_id'`) sends
`x-amz-server-side-encryption` on every object. Without it the bucket's default
encryption applies.

## MinIO and Cloudflare R2

Pass the store's `https://` endpoint as `endpointUrl` — for R2,
`https://<account-id>.r2.cloudflarestorage.com` with region `auto`. A custom endpoint
is SSRF-checked at registration and on every request, so it must be publicly
resolvable; plain `http://` is refused. Custom endpoints use path-style addressing
(`https://endpoint/bucket/key`); set `'path_style' => false` for virtual-hosted.

## How requests are signed

Every request is signed with AWS Signature Version 4 (header-based, with
`x-amz-content-sha256` so S3 verifies the payload). The signer is a small in-package
implementation on PHP's `hash_hmac`, checked against AWS's published SigV4 test
vectors — the AWS SDK is not a dependency. Instance-profile or web-identity
credentials can be plugged in by rebinding `Contracts\AwsCredentialResolver` (see
[custom sink](../extension-points/custom-sink.md)).

## Failures

| Response | Meaning | Handling |
|----------|---------|----------|
| 403 `AccessDenied`, `InvalidAccessKeyId`, `SignatureDoesNotMatch` | credentials refused | circuit opens, `action_required` |
| 404 `NoSuchBucket`, 301 `PermanentRedirect`, `AuthorizationHeaderMalformed` | wrong bucket/region/endpoint | circuit opens, `action_required` |
| `ExpiredToken` | temporary credentials expired | cache dropped, retried |
| 5xx, `SlowDown`, timeouts | transient | retried with backoff |
