<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Cbox\Siem\Enums\EventCategory;
use Cbox\Siem\Enums\Outcome;
use Cbox\Siem\Enums\Severity;
use Cbox\Siem\ValueObjects\Party;
use Cbox\Siem\ValueObjects\SiemEvent;
use DateTimeImmutable;

/**
 * Losslessly (de)serializes a {@see SiemEvent} to and from the JSON-safe array
 * stored in an outbox row. The timestamp is preserved with microsecond precision
 * and its offset, so the formatter emits the exact same wire bytes whether it runs
 * at dispatch time or later from the queue.
 */
class SiemEventSerializer
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(SiemEvent $event): array
    {
        return [
            'id' => $event->id,
            'occurred_at' => $event->occurredAt->format('Y-m-d\TH:i:s.uP'),
            'action' => $event->action,
            'category' => $event->category->value,
            'outcome' => $event->outcome->value,
            'severity' => $event->severity->value,
            'actor' => $event->actor === null ? null : ['type' => $event->actor->type, 'id' => $event->actor->id],
            'target' => $event->target === null ? null : ['type' => $event->target->type, 'id' => $event->target->id],
            'source_ip' => $event->sourceIp,
            'message' => $event->message,
            'context' => $event->context,
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public function fromArray(array $data): SiemEvent
    {
        return new SiemEvent(
            id: self::string($data, 'id'),
            occurredAt: new DateTimeImmutable(self::string($data, 'occurred_at')),
            action: self::string($data, 'action'),
            category: EventCategory::from(self::string($data, 'category')),
            outcome: Outcome::from(self::string($data, 'outcome')),
            severity: Severity::from(self::string($data, 'severity')),
            actor: self::party($data['actor'] ?? null),
            target: self::party($data['target'] ?? null),
            sourceIp: self::nullableString($data['source_ip'] ?? null),
            message: self::nullableString($data['message'] ?? null),
            context: self::context($data['context'] ?? []),
        );
    }

    private static function party(mixed $value): ?Party
    {
        if (! is_array($value)) {
            return null;
        }

        $type = $value['type'] ?? null;
        $id = $value['id'] ?? null;

        if (! is_string($type) || ! is_string($id)) {
            return null;
        }

        return new Party($type, $id);
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        return is_string($value) ? $value : '';
    }

    private static function nullableString(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }

    /**
     * @return array<string, scalar|null>
     */
    private static function context(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $out = [];

        foreach ($value as $key => $item) {
            if (is_string($key) && (is_scalar($item) || $item === null)) {
                $out[$key] = $item;
            }
        }

        return $out;
    }
}
