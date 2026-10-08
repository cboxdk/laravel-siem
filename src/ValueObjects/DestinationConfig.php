<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\ValueObjects;

use Cbox\LaravelSiem\Support\DestinationSettings;

/**
 * A stream's validated, normalized destination settings — what the registry
 * stores: the endpoint to SSRF-check and dial, and the `options` bag (empty for
 * the HTTP collectors). Produced by {@see DestinationSettings}.
 */
readonly class DestinationConfig
{
    /**
     * @param  array<string, string|bool>  $options
     */
    public function __construct(
        public string $endpoint = '',
        public array $options = [],
    ) {}
}
