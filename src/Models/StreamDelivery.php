<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Models;

use Cbox\LaravelSiem\Enums\DeliveryStatus;
use Cbox\Siem\ValueObjects\SiemEvent;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * One row of the transactional outbox: a single {@see SiemEvent}
 * queued for one {@see LogStream}. The dispatcher inserts these as a cheap insert
 * inside the caller's own database transaction, so the audit write and the
 * intent-to-deliver commit atomically — that is exactly what makes the delivery
 * guarantee at-least-once (a rolled-back caller leaves no orphan row). The queued
 * pump later claims, formats, and ships them.
 *
 * @property string $id
 * @property string $stream_id
 * @property array<string, mixed> $payload
 * @property DeliveryStatus $status
 * @property int $attempts
 * @property Carbon|null $next_attempt_at
 * @property string|null $last_error
 * @property Carbon|null $delivered_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class StreamDelivery extends Model
{
    use HasUlids;

    protected $table = 'stream_deliveries';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'payload' => 'array',
            'status' => DeliveryStatus::class,
            'attempts' => 'integer',
            'next_attempt_at' => 'datetime',
            'delivered_at' => 'datetime',
        ];
    }
}
