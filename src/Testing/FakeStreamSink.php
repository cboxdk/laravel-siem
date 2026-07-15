<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Testing;

use Cbox\LaravelSiem\Exceptions\StreamDeliveryFailed;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\ValueObjects\StreamTarget;
use RuntimeException;

/**
 * An in-memory {@see StreamSink} for driving the delivery engine in tests without
 * a network. It captures every successful batch (the records and the target), and
 * can be programmed to FAIL for chosen targets so retry, dead-letter, and circuit
 * breaker behaviour is exercised deterministically. This is the dogfooded stand-in
 * the package's own suite uses.
 */
class FakeStreamSink implements StreamSink
{
    /** @var list<array{target: StreamTarget, records: list<string>}> */
    private array $batches = [];

    /** @var list<string> */
    private array $failingTargets = [];

    private bool $failAll = false;

    private ?int $failAfter = null;

    private int $sendCount = 0;

    public function send(iterable $formattedRecords, StreamTarget $target): void
    {
        $this->sendCount++;

        $failByCount = $this->failAfter !== null && $this->sendCount > $this->failAfter;

        if ($this->failAll || $failByCount || in_array($target->name, $this->failingTargets, true)) {
            throw new StreamDeliveryFailed("fake sink: delivery to [{$target->name}] failed");
        }

        $records = [];
        foreach ($formattedRecords as $record) {
            $records[] = $record;
        }

        $this->batches[] = ['target' => $target, 'records' => $records];
    }

    /**
     * Make delivery to the named target(s) throw, simulating a down destination.
     */
    public function failFor(string ...$targetNames): self
    {
        $this->failingTargets = [...$this->failingTargets, ...array_values($targetNames)];

        return $this;
    }

    public function failEverything(): self
    {
        $this->failAll = true;

        return $this;
    }

    /**
     * Let the first `$n` batch sends succeed, then fail every send after that —
     * simulating a destination that accepts some traffic and then fails a later
     * batch within the same pump run (order-independent, unlike {@see failFor()}).
     */
    public function failAfter(int $n): self
    {
        $this->failAfter = $n;

        return $this;
    }

    /**
     * @return list<array{target: StreamTarget, records: list<string>}>
     */
    public function batches(): array
    {
        return $this->batches;
    }

    /**
     * @return list<string>
     */
    public function records(): array
    {
        if ($this->batches === []) {
            return [];
        }

        return array_merge(...array_map(
            static fn (array $batch): array => $batch['records'],
            $this->batches,
        ));
    }

    public function assertNothingSent(): void
    {
        if ($this->batches !== []) {
            throw new RuntimeException('Expected nothing to be sent, but at least one batch was.');
        }
    }

    public function assertSentTo(string $targetName): void
    {
        foreach ($this->batches as $batch) {
            if ($batch['target']->name === $targetName) {
                return;
            }
        }

        throw new RuntimeException("Expected a batch to be sent to target [{$targetName}], but none was.");
    }

    /**
     * Assert no shipped record contains the given raw substring — the redaction
     * guarantee (a sensitive value must never reach the sink).
     */
    public function assertNoRecordContains(string $needle): void
    {
        foreach ($this->records() as $record) {
            if (str_contains($record, $needle)) {
                throw new RuntimeException("Expected no record to contain [{$needle}], but one did.");
            }
        }
    }

    /**
     * @param  callable(string): bool  $predicate
     */
    public function assertSent(callable $predicate): void
    {
        foreach ($this->records() as $record) {
            if ($predicate($record)) {
                return;
            }
        }

        throw new RuntimeException('Expected a sent record to match the predicate, but none did.');
    }
}
