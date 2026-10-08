<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support\Aws;

/**
 * Reads single leaf values (`<Code>`, `<AccessKeyId>`, …) out of the small, fixed
 * XML documents S3 and STS answer with. A full XML parser (and the ext-simplexml /
 * ext-dom requirement it brings) is not needed for leaf elements whose values are
 * plain text; entities are decoded, nothing is evaluated, no external entity is
 * ever resolved.
 */
final class AwsXml
{
    public static function value(string $xml, string $element): ?string
    {
        $pattern = '#<'.preg_quote($element, '#').'>([^<]*)</'.preg_quote($element, '#').'>#';

        if (preg_match($pattern, $xml, $match) !== 1) {
            return null;
        }

        $value = trim(html_entity_decode($match[1], ENT_QUOTES | ENT_XML1, 'UTF-8'));

        return $value === '' ? null : $value;
    }
}
