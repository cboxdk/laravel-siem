<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Exceptions;

use InvalidArgumentException;

/**
 * A stream's destination settings are incomplete or malformed (a missing bucket,
 * an unknown Datadog site, an unparseable service-account key, …). Thrown by the
 * registry before anything is stored; `field` names the offending option so a
 * host can attach the message to the right form field. Never carries a secret.
 */
class InvalidStreamConfiguration extends InvalidArgumentException
{
    public function __construct(string $message, public readonly string $field = 'options')
    {
        parent::__construct($message);
    }

    public static function for(string $field, string $message): self
    {
        return new self($message, $field);
    }
}
