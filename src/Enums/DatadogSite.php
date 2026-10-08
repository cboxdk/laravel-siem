<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Enums;

/**
 * The Datadog site an organization's account lives on. Each site has its own logs
 * intake host; an API key only works against its own site.
 */
enum DatadogSite: string
{
    case Us1 = 'datadoghq.com';
    case Us3 = 'us3.datadoghq.com';
    case Us5 = 'us5.datadoghq.com';
    case Eu1 = 'datadoghq.eu';
    case Ap1 = 'ap1.datadoghq.com';
    case Ap2 = 'ap2.datadoghq.com';
    case Gov = 'ddog-gov.com';

    /**
     * The Logs intake API v2 endpoint for this site.
     */
    public function intakeUrl(): string
    {
        return 'https://http-intake.logs.'.$this->value.'/api/v2/logs';
    }
}
