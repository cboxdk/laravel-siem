<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Cbox\LaravelSiem\Enums\Destination;
use Cbox\Siem\Contracts\StreamFormatter;
use Cbox\Siem\Formatters\CefFormatter;
use Cbox\Siem\Formatters\EcsFormatter;
use Cbox\Siem\Formatters\GelfFormatter;
use Cbox\Siem\Formatters\JsonFormatter;
use Cbox\Siem\Formatters\SplunkHecFormatter;

/**
 * Selects the pure core formatter for a destination. This is the only place the
 * wrapper decides which SIEM schema a stream speaks; the formatters themselves
 * live in `cboxdk/siem` and remain framework-agnostic and side-effect-free.
 */
class FormatterFactory
{
    public function for(Destination $destination): StreamFormatter
    {
        return match ($destination) {
            Destination::SplunkHec => new SplunkHecFormatter,
            Destination::ElasticEcs => new EcsFormatter,
            Destination::GraylogGelf => new GelfFormatter($this->host()),
            Destination::CefHttp => new CefFormatter,
            Destination::GenericJson => new JsonFormatter,
        };
    }

    private function host(): string
    {
        $name = config('app.name', 'cbox-siem');

        return is_string($name) && $name !== '' ? $name : 'cbox-siem';
    }
}
