<?php

declare(strict_types=1);

use Cbox\LaravelSiem\Support\Aws\SigV4Signer;
use Cbox\LaravelSiem\ValueObjects\AwsCredentials;

/*
 * AWS's published Signature Version 4 vectors — the signer must reproduce them
 * byte for byte. Sources: the AWS SigV4 test suite (get-vanilla, post-vanilla,
 * get-vanilla-query-order-key-case; credentials AKIDEXAMPLE), the "deriving the
 * signing key" example from the SigV4 reference, and the two worked examples in
 * the Amazon S3 API reference ("Signature calculation: Authorization header",
 * GET Object and PUT Object, credentials AKIAIOSFODNN7EXAMPLE).
 */

const SUITE_SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
const S3_DOC_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

function suiteSign(string $method, string $url): string
{
    return (new SigV4Signer)->sign(
        $method, $url, [], hash('sha256', ''),
        new AwsCredentials('AKIDEXAMPLE', SUITE_SECRET),
        'us-east-1', 'service', new DateTimeImmutable('2015-08-30T12:36:00Z'),
    )['Authorization'];
}

it('reproduces the SigV4 test-suite vectors', function (string $method, string $url, string $signature): void {
    expect(suiteSign($method, $url))->toBe(
        'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature='.$signature,
    );
})->with([
    'get-vanilla' => ['GET', 'https://example.amazonaws.com/', '5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31'],
    'post-vanilla' => ['POST', 'https://example.amazonaws.com/', '5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b'],
    'get-vanilla-query-order-key-case' => ['GET', 'https://example.amazonaws.com/?Param2=value2&Param1=value1', 'b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500'],
]);

it('derives the documented signing key', function (): void {
    $key = (new SigV4Signer)->signingKey(SUITE_SECRET, '20120215', 'us-east-1', 'iam');

    expect(bin2hex($key))->toBe('f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d');
});

it('reproduces the S3 GET Object example', function (): void {
    $empty = hash('sha256', '');

    $headers = (new SigV4Signer)->sign(
        'GET', 'https://examplebucket.s3.amazonaws.com/test.txt',
        ['Range' => 'bytes=0-9', 'x-amz-content-sha256' => $empty], $empty,
        new AwsCredentials('AKIAIOSFODNN7EXAMPLE', S3_DOC_SECRET),
        'us-east-1', 's3', new DateTimeImmutable('2013-05-24T00:00:00Z'),
    );

    expect($headers['Authorization'])->toBe(
        'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, '
        .'SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, '
        .'Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41',
    )->and($headers['X-Amz-Date'])->toBe('20130524T000000Z');
});

it('reproduces the S3 PUT Object example (URI-encoded key)', function (): void {
    $payloadHash = hash('sha256', 'Welcome to Amazon S3.');

    $headers = (new SigV4Signer)->sign(
        'PUT', 'https://examplebucket.s3.amazonaws.com/test$file.text',
        [
            'Date' => 'Fri, 24 May 2013 00:00:00 GMT',
            'x-amz-storage-class' => 'REDUCED_REDUNDANCY',
            'x-amz-content-sha256' => $payloadHash,
        ],
        $payloadHash,
        new AwsCredentials('AKIAIOSFODNN7EXAMPLE', S3_DOC_SECRET),
        'us-east-1', 's3', new DateTimeImmutable('2013-05-24T00:00:00Z'),
    );

    expect($payloadHash)->toBe('44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072')
        ->and($headers['Authorization'])->toEndWith(
            'SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, '
            .'Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd',
        );
});

it('signs the session token of temporary credentials', function (): void {
    $headers = (new SigV4Signer)->sign(
        'PUT', 'https://bucket.s3.eu-west-1.amazonaws.com/k', [], hash('sha256', ''),
        new AwsCredentials('ASIATEMP', 'secret', 'session-token-value'),
        'eu-west-1', 's3', new DateTimeImmutable('2026-10-08T10:00:00Z'),
    );

    expect($headers['X-Amz-Security-Token'])->toBe('session-token-value')
        ->and($headers['Authorization'])->toContain('SignedHeaders=host;x-amz-date;x-amz-security-token,');
});

it('never puts the secret key into the headers it returns', function (): void {
    $headers = (new SigV4Signer)->sign(
        'PUT', 'https://bucket.s3.eu-west-1.amazonaws.com/k', [], hash('sha256', ''),
        new AwsCredentials('AKIAEXAMPLE', 'super-secret-access-key'),
        'eu-west-1', 's3', new DateTimeImmutable('2026-10-08T10:00:00Z'),
    );

    expect(implode("\n", $headers))->not->toContain('super-secret-access-key');
});
