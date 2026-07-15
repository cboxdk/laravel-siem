<?php

declare(strict_types=1);

namespace Cbox\LaravelSiem\Models;

use Cbox\LaravelSiem\Enums\AuthScheme;
use Cbox\LaravelSiem\Enums\Destination;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A configured SIEM destination: where formatted security events are shipped and
 * how. This model is deliberately tenancy-AGNOSTIC — `owner_key` is a nullable,
 * uninterpreted seam a host can scope by (an environment id, an organization id,
 * a team slug); the package never assumes what it means. A host that needs
 * tenant isolation subclasses this model (resolved through `config('siem.models')`)
 * and adds the scope.
 *
 * The `secret` (a Splunk HEC token, a bearer token, or an HMAC signing key) is
 * stored with Laravel's `encrypted` cast, so it is ciphertext at rest and only
 * decrypted in memory at delivery time — it is never logged or persisted in an
 * error payload.
 *
 * @property string $id
 * @property string $name
 * @property Destination $destination
 * @property string $endpoint_url
 * @property string|null $secret
 * @property AuthScheme $auth
 * @property string|null $owner_key
 * @property array<string, mixed>|null $filters
 * @property array<string, mixed>|null $redaction
 * @property bool $enabled
 * @property Carbon|null $last_success_at
 * @property int $consecutive_failures
 * @property Carbon|null $circuit_opened_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class LogStream extends Model
{
    use HasUlids;

    protected $table = 'log_streams';

    protected $guarded = [];

    /**
     * The already-flattened per-field redaction policy for this stream, keyed by
     * context field name (`{"password": "drop", "email": "hash"}`).
     *
     * @return array<string, mixed>
     */
    public function redactionPolicy(): array
    {
        return is_array($this->redaction) ? $this->redaction : [];
    }

    /**
     * The action allow/deny filter for this stream. `{"allow": [...]}` ships only
     * the listed actions (deny-by-default within the filter); `{"deny": [...]}`
     * ships everything except the listed actions.
     *
     * @return array<string, mixed>
     */
    public function filterPolicy(): array
    {
        return is_array($this->filters) ? $this->filters : [];
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'destination' => Destination::class,
            'auth' => AuthScheme::class,
            'secret' => 'encrypted',
            'filters' => 'array',
            'redaction' => 'array',
            'enabled' => 'boolean',
            'consecutive_failures' => 'integer',
            'last_success_at' => 'datetime',
            'circuit_opened_at' => 'datetime',
        ];
    }
}
