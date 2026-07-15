<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Support;

use Cbox\LaravelSiem\Enums\RedactionAction;
use Cbox\Siem\ValueObjects\SiemEvent;

/**
 * Applies a stream's per-field redaction policy to a {@see SiemEvent} BEFORE it is
 * formatted, returning a new event — the core formatters stay pure and never see
 * the raw value. The policy is keyed by field name; `context.*` keys are matched
 * directly, and the top-level `message` and `source_ip` fields are matchable too.
 * A configured sensitive field is never streamed raw: it is hashed (stable
 * SHA-256, correlatable), masked, or dropped.
 */
class Redactor
{
    private const string MASK = '[REDACTED]';

    /**
     * @param  array<string, mixed>  $policy  field name => hash|mask|drop
     */
    public function redact(SiemEvent $event, array $policy): SiemEvent
    {
        if ($policy === []) {
            return $event;
        }

        $context = $event->context;

        foreach ($context as $key => $value) {
            $action = $this->actionFor($policy, $key);

            if ($action === null) {
                continue;
            }

            if ($action === RedactionAction::Drop) {
                unset($context[$key]);

                continue;
            }

            $context[$key] = $this->apply($action, $value);
        }

        $message = $event->message;
        $messageAction = $this->actionFor($policy, 'message');
        if ($messageAction !== null && $message !== null) {
            $message = $messageAction === RedactionAction::Drop ? null : $this->apply($messageAction, $message);
        }

        $sourceIp = $event->sourceIp;
        $ipAction = $this->actionFor($policy, 'source_ip');
        if ($ipAction !== null && $sourceIp !== null) {
            $sourceIp = $ipAction === RedactionAction::Drop ? null : $this->apply($ipAction, $sourceIp);
        }

        return new SiemEvent(
            id: $event->id,
            occurredAt: $event->occurredAt,
            action: $event->action,
            category: $event->category,
            outcome: $event->outcome,
            severity: $event->severity,
            actor: $event->actor,
            target: $event->target,
            sourceIp: $sourceIp,
            message: $message,
            context: $context,
        );
    }

    /**
     * @param  array<string, mixed>  $policy
     */
    private function actionFor(array $policy, string $field): ?RedactionAction
    {
        $value = $policy[$field] ?? null;

        return is_string($value) ? RedactionAction::tryFrom($value) : null;
    }

    private function apply(RedactionAction $action, string|int|float|bool|null $value): string
    {
        return match ($action) {
            RedactionAction::Mask, RedactionAction::Drop => self::MASK,
            RedactionAction::Hash => hash('sha256', $this->stringify($value)),
        };
    }

    private function stringify(string|int|float|bool|null $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        return (string) ($value ?? '');
    }
}
