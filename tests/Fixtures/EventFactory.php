<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Tests\Fixtures;

use Cbox\Siem\Enums\EventCategory;
use Cbox\Siem\Enums\Outcome;
use Cbox\Siem\Enums\Severity;
use Cbox\Siem\ValueObjects\Party;
use Cbox\Siem\ValueObjects\SiemEvent;
use DateTimeImmutable;

/**
 * Builds {@see SiemEvent}s for the delivery-engine tests.
 */
class EventFactory
{
    /**
     * @param  array<string, scalar|null>  $context
     */
    public static function make(
        string $action = 'user-login',
        array $context = [],
        string $id = 'evt_1',
    ): SiemEvent {
        return new SiemEvent(
            id: $id,
            occurredAt: new DateTimeImmutable('2026-07-15T12:00:00.000000+00:00'),
            action: $action,
            category: EventCategory::Authentication,
            outcome: Outcome::Success,
            severity: Severity::Info,
            actor: Party::of('user', '42'),
            target: null,
            sourceIp: '203.0.113.10',
            message: 'a user logged in',
            context: $context,
        );
    }
}
