---
title: Stream to Google Cloud Storage
weight: 5
description: Archive events to a Google Cloud Storage bucket as time-partitioned NDJSON objects, authorized by a service-account key with roles/storage.objectCreator.
---

# Stream to Google Cloud Storage

Objects use the same layout as S3:
`{prefix}/{yyyy}/{mm}/{dd}/{hh}/{batch-id}.ndjson.gz` (UTC hour of the write, fresh
ULID per object, gzip unless `gzip => false`).

## 1. A service account that can only create objects

```bash
gcloud iam service-accounts create siem-writer --project=acme-audit

gcloud storage buckets add-iam-policy-binding gs://acme-audit-logs \
  --member="serviceAccount:siem-writer@acme-audit.iam.gserviceaccount.com" \
  --role="roles/storage.objectCreator"

gcloud iam service-accounts keys create siem-writer-key.json \
  --iam-account=siem-writer@acme-audit.iam.gserviceaccount.com
```

`roles/storage.objectCreator` on the bucket allows creating objects and nothing else
— no read, list, overwrite or delete. Grant it on the bucket, not the project.

## 2. Register the stream

```php
app(LogStreams::class)->create(
    name: 'gcs-archive',
    destination: Destination::Gcs,
    endpointUrl: '',                                       // https://storage.googleapis.com
    secret: file_get_contents('siem-writer-key.json'),    // stored encrypted
    options: ['bucket' => 'acme-audit-logs', 'prefix' => 'cbox/audit'],
);
```

The key is validated at registration (a `service_account` key with a usable private
key) and never echoed in an error.

## How it authenticates

The sink signs a one-hour JWT (`iss` = the service account, `aud` = the token
endpoint, scope `devstorage.read_write`) with the key's private key — RS256 through
PHP's OpenSSL — and exchanges it for an access token (the RFC 7523 JWT-bearer
grant). The token is cached, encrypted with the app key, until a minute before it
expires. IAM, not the scope, is what limits the account to creating objects.

The token endpoint is always `siem.gcs.token_uri` (Google's by default). A key file's
own `token_uri` is ignored, so a crafted key cannot choose where the platform sends a
signed request.

## Failures

| Response | Meaning | Handling |
|----------|---------|----------|
| token exchange `invalid_grant` / `invalid_client` | key deleted, disabled, wrong project | circuit opens, `action_required` |
| upload 401 | token rejected | token dropped, circuit opens |
| upload 403 | account lacks `storage.objects.create` | circuit opens, `action_required` |
| upload 404 | no such bucket | circuit opens, `action_required` |
| 429, 5xx, timeouts | transient | retried with backoff |
