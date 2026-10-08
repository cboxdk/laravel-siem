<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem;

use Cbox\LaravelSiem\Contracts\StreamTester;
use Cbox\LaravelSiem\Enums\FailureKind;
use Cbox\LaravelSiem\Exceptions\DestinationRefused;
use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\Support\CircuitBreaker;
use Cbox\LaravelSiem\Support\FormatterFactory;
use Cbox\LaravelSiem\Support\Redactor;
use Cbox\LaravelSiem\Support\SecretScrubber;
use Cbox\LaravelSiem\Support\StreamTargetFactory;
use Cbox\LaravelSiem\ValueObjects\TestDeliveryResult;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\Enums\EventCategory;
use Cbox\Siem\Enums\Outcome;
use Cbox\Siem\Enums\Severity;
use Cbox\Siem\ValueObjects\SiemEvent;
use DateTimeImmutable;
use Illuminate\Support\Str;
use Throwable;

/**
 * The default {@see StreamTester}: formats one marker event (action
 * `siem.stream.test`, a fresh id, a message saying it is safe to ignore) with the
 * stream's formatter and redaction, and sends it through the bound
 * {@see StreamSink} exactly as the pump would — same target, same SSRF guard,
 * same credentials — but synchronously and outside the outbox.
 */
class SinkStreamTester implements StreamTester
{
    public const string ACTION = 'siem.stream.test';

    public function __construct(
        private readonly StreamSink $sink,
        private readonly FormatterFactory $formatters,
        private readonly Redactor $redactor,
        private readonly CircuitBreaker $breaker,
        private readonly StreamTargetFactory $targets = new StreamTargetFactory,
        private readonly SecretScrubber $scrubber = new SecretScrubber,
    ) {}

    public function test(LogStream $stream): TestDeliveryResult
    {
        $event = $this->marker($stream);
        $formatter = $this->formatters->for($stream->destination);
        $record = $formatter->format($this->redactor->redact($event, $stream->redactionPolicy()));

        try {
            $this->sink->send([$record], $this->targets->for($stream, $formatter));
        } catch (DestinationRefused $e) {
            return TestDeliveryResult::failed($e->kind, $this->scrubber->scrub($e->getMessage(), $stream->secret), $event->id);
        } catch (Throwable $e) {
            return TestDeliveryResult::failed(FailureKind::Transient, $this->scrubber->scrub($e->getMessage(), $stream->secret), $event->id);
        }

        // The destination accepted it: the stream works now, so stop waiting out
        // a cooldown or showing "action required".
        if ($stream->consecutive_failures > 0 || $stream->circuit_opened_at !== null) {
            $this->breaker->recordSuccess($stream);
            $stream->save();
        }

        return TestDeliveryResult::delivered($event->id);
    }

    private function marker(LogStream $stream): SiemEvent
    {
        return new SiemEvent(
            id: 'siem-test-'.strtolower((string) Str::ulid()),
            occurredAt: new DateTimeImmutable,
            action: self::ACTION,
            category: EventCategory::Audit,
            outcome: Outcome::Success,
            severity: Severity::Info,
            message: 'Test event for log stream "'.$stream->name.'" — safe to ignore.',
            context: ['test' => true, 'stream' => $stream->name],
        );
    }
}
