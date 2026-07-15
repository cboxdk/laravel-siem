<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem;

use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\LaravelSiem\Enums\DeliveryStatus;
use Cbox\LaravelSiem\Events\OutboxOverflowed;
use Cbox\LaravelSiem\Models\LogStream;
use Cbox\LaravelSiem\Models\StreamDelivery;
use Cbox\LaravelSiem\Support\ActionFilter;
use Cbox\LaravelSiem\Support\Config;
use Cbox\LaravelSiem\Support\ModelClass;
use Cbox\LaravelSiem\Support\SiemEventSerializer;
use Cbox\Siem\ValueObjects\SiemEvent;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;

/**
 * The transactional-outbox writer. For each stream whose action filter admits the
 * event it writes one cheap `pending` row (an insert, no network). Run it inside
 * the caller's own transaction so the audit write and the outbox row commit
 * atomically — that is what makes at-least-once hold. The outbox is bounded per
 * stream (backpressure): once `max_pending` is reached the configured policy sheds
 * rows by dead-lettering them, logs a warning, and fires {@see OutboxOverflowed}.
 */
class DatabaseStreamDispatcher implements StreamDispatcher
{
    public function __construct(
        private readonly ActionFilter $filter = new ActionFilter,
        private readonly SiemEventSerializer $serializer = new SiemEventSerializer,
    ) {}

    public function dispatch(SiemEvent $event, iterable $streams): int
    {
        $payload = $this->serializer->toArray($event);
        $written = 0;

        foreach ($streams as $stream) {
            if (! $stream->enabled) {
                continue;
            }

            if (! $this->filter->admits($stream->filterPolicy(), $event->action)) {
                continue;
            }

            if ($this->applyBackpressure($stream) === 'reject_new') {
                $this->write($stream->id, $payload, DeliveryStatus::Dead, 'shed by backpressure policy: reject_new');
                $written++;

                continue;
            }

            $this->write($stream->id, $payload, DeliveryStatus::Pending, null);
            $written++;
        }

        return $written;
    }

    /**
     * Enforce the outbox bound for one stream. Returns the effective policy string
     * ('drop_oldest', 'reject_new', or 'ok' when under the bound).
     */
    private function applyBackpressure(LogStream $stream): string
    {
        $maxPending = max(1, Config::int('siem.backpressure.max_pending', 100000));
        $class = $this->deliveryClass();

        $pending = $class::query()
            ->where('stream_id', $stream->id)
            ->where('status', DeliveryStatus::Pending->value)
            ->count();

        if ($pending < $maxPending) {
            return 'ok';
        }

        $policyRaw = config('siem.backpressure.policy', 'drop_oldest');
        $policy = $policyRaw === 'reject_new' ? 'reject_new' : 'drop_oldest';

        if ($policy === 'reject_new') {
            $this->reportOverflow($stream, 1, $policy, $pending);

            return 'reject_new';
        }

        // drop_oldest: dead-letter the oldest pending rows to make room for the new
        // event, keeping the freshest security signal.
        $shedCount = $pending - $maxPending + 1;
        $oldest = $class::query()
            ->where('stream_id', $stream->id)
            ->where('status', DeliveryStatus::Pending->value)
            ->orderBy('created_at')
            ->orderBy('id')
            ->limit($shedCount)
            ->pluck('id')
            ->all();

        if ($oldest !== []) {
            $class::query()->whereIn('id', $oldest)->update([
                'status' => DeliveryStatus::Dead->value,
                'last_error' => 'shed by backpressure policy: drop_oldest',
            ]);
        }

        $this->reportOverflow($stream, count($oldest), $policy, $pending);

        return 'drop_oldest';
    }

    private function reportOverflow(LogStream $stream, int $shed, string $policy, int $pending): void
    {
        Log::warning('siem: outbox backpressure shed deliveries', [
            'stream_id' => $stream->id,
            'owner_key' => $stream->owner_key,
            'shed' => $shed,
            'policy' => $policy,
            'pending' => $pending,
        ]);

        Event::dispatch(new OutboxOverflowed($stream->id, $stream->owner_key, $shed, $policy, $pending));
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function write(string $streamId, array $payload, DeliveryStatus $status, ?string $error): void
    {
        $class = $this->deliveryClass();
        $delivery = new $class;
        $delivery->fill([
            'stream_id' => $streamId,
            'payload' => $payload,
            'status' => $status,
            'attempts' => 0,
            'last_error' => $error,
        ]);
        $delivery->save();
    }

    /**
     * @return class-string<StreamDelivery>
     */
    private function deliveryClass(): string
    {
        return ModelClass::resolve('siem.models.stream_delivery', StreamDelivery::class);
    }
}
